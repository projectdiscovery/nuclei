package mongo

import (
	"context"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"go.mongodb.org/mongo-driver/mongo"
	"net/url"
	"os"
	"strings"
	"sync"

	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

type Exporter struct {
	options    *Options
	mutex      *sync.Mutex
	rows       []output.ResultEvent
	collection *mongo.Collection
	connection *mongo.Client
}

// Options contains the configuration options for MongoDB exporter client
type Options struct {
	// ConnectionString is the connection string to the MongoDB database
	ConnectionString string `yaml:"connection-string"`
	// CollectionName is the name of the MongoDB collection in which to store the results
	CollectionName string `yaml:"collection-name"`
	// OmitRaw excludes the Request and Response from the results (helps with filesize)
	OmitRaw bool `yaml:"omit-raw"`
	// BatchSize determines the number of results to be kept in memory before writing it to the database or 0 to
	//	persist all in memory and write all results at the end (default)
	BatchSize int `yaml:"batch-size"`
}

// New creates a new MongoDB exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []output.ResultEvent{},
	}

	// If the environment variable for the connection string is set, then use that instead. This allows for easier
	// management of sensitive items such as credentials
	envConnectionString := os.Getenv("MONGO_CONNECTION_STRING")
	if envConnectionString != "" {
		options.ConnectionString = envConnectionString
		gologger.Info().Msgf("Using connection string from environment variable MONGO_CONNECTION_STRING")
	}

	// Create the connection to the database
	clientOptions := mongooptions.Client().ApplyURI(options.ConnectionString)

	// Create a new client and connect to the MongoDB server
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		gologger.Error().Msgf("Error creating MongoDB client: %s", err)
		return nil, err
	}

	// Ensure the connection is valid
	err = client.Ping(context.Background(), nil)
	if err != nil {
		gologger.Error().Msgf("Error connecting to MongoDB: %s", err)
		return nil, err
	}

	// Get the database from the connection string to set the database and collection
	parsed, err := url.Parse(options.ConnectionString)
	if err != nil {
		gologger.Error().Msgf("Error parsing connection string: %s", options.ConnectionString)
		return nil, err
	}

	databaseName := strings.TrimPrefix(parsed.Path, "/")

	if databaseName == "" {
		return nil, errors.New("error getting database name from connection string")
	}

	exporter.connection = client
	exporter.collection = client.Database(databaseName).Collection(options.CollectionName)

	return exporter, nil
}

// Export writes a result document to the configured MongoDB collection
// in the database configured by the connection string
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if exporter.options.OmitRaw {
		event.Request = ""
		event.Response = ""
	}

	// Add the row to the queue to be processed
	exporter.rows = append(exporter.rows, *event)

	// If the batch size is greater than 0 and the number of rows has reached the batch, flush it to the database
	if exporter.options.BatchSize > 0 && len(exporter.rows) >= exporter.options.BatchSize {
		err := exporter.WriteRows()
		if err != nil {
			// The error is already logged, return it to bubble up to the caller
			return err
		}
	}

	return nil
}

// WriteRows writes all rows from the rows list to the MongoDB collection and removes them from the list
func (exporter *Exporter) WriteRows() error {
	// Loop through the rows and write them, removing them as they're entered
	for len(exporter.rows) > 0 {
		data := exporter.rows[0]

		// Write the data to the database
		_, err := exporter.collection.InsertOne(context.TODO(), data)
		if err != nil {
			gologger.Fatal().Msgf("Error inserting record into MongoDB collection: %s", err)
			return err
		}

		// Remove the item from the list
		exporter.rows = exporter.rows[1:]
	}

	return nil
}

func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Write all pending rows
	err := exporter.WriteRows()
	if err != nil {
		// The error is already logged, return it to bubble up to the caller
		return err
	}

	// Close the database connection
	err = exporter.connection.Disconnect(context.TODO())
	if err != nil {
		gologger.Error().Msgf("Error disconnecting from MongoDB: %s", err)
		return err
	}

	return nil
}
