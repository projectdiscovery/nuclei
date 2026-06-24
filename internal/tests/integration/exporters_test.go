//go:build integration
// +build integration

package integration_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/mongo"
	osutil "github.com/projectdiscovery/utils/os"
	mongoclient "go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

const (
	dbName                    = "test"
	dbRepository              = "mongo"
	dbTag                     = "8"
	dbPort                    = "27017/tcp"
	mongoDatabaseReadyTimeout = 3 * time.Minute
	mongoServerSelectionDelay = time.Second
)

var exportersTestCases = []integrationCase{
	{Path: "exporters/mongo", TestCase: &mongoExporter{}, DisableOn: func() bool {
		return osutil.IsWindows() || osutil.IsOSX()
	}},
}

type mongoExporter struct{}

func (m *mongoExporter) Execute(filepath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := dockertest.NewPool("")
	if err != nil {
		return fmt.Errorf("could not create docker pool: %w", err)
	}
	if err := pool.Client.Ping(); err != nil {
		return fmt.Errorf("could not connect to Docker: %w", err)
	}
	pool.MaxWait = mongoDatabaseReadyTimeout

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   dbRepository,
		Tag:          dbTag,
		ExposedPorts: []string{dbPort},
	})
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}
	defer purge(pool, resource)

	mappedPort := resource.GetPort(dbPort)
	if mappedPort == "" {
		return fmt.Errorf("missing mapped port for %s", dbPort)
	}
	connString := fmt.Sprintf("mongodb://%s/%s", net.JoinHostPort("127.0.0.1", mappedPort), dbName)

	err = pool.Retry(func() error {
		clientOptions := mongooptions.Client().ApplyURI(connString).SetServerSelectionTimeout(mongoServerSelectionDelay)
		client, err := mongoclient.Connect(ctx, clientOptions)
		if err != nil {
			return err
		}
		defer client.Disconnect(ctx)
		return client.Ping(ctx, nil)
	})
	if err != nil {
		return fmt.Errorf("failed to wait for MongoDB container: %w", err)
	}

	// Create a MongoDB exporter and write a test result to the database
	opts := mongo.Options{
		ConnectionString: connString,
		CollectionName:   "test",
		BatchSize:        1, // Ensure we write the result immediately
	}

	exporter, err := mongo.New(&opts)
	if err != nil {
		return fmt.Errorf("failed to create MongoDB exporter: %s", err)
	}
	defer func() {
		if err := exporter.Close(); err != nil {
			fmt.Printf("failed to close exporter: %s\n", err)
		}
	}()

	res := &output.ResultEvent{
		Request:  "test request",
		Response: "test response",
	}

	err = exporter.Export(res)
	if err != nil {
		return fmt.Errorf("failed to export result event to MongoDB: %s", err)
	}

	// Verify that the result was written to the database
	clientOptions := mongooptions.Client().ApplyURI(connString)
	client, err := mongoclient.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("error creating MongoDB client: %s", err)
	}
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			fmt.Printf("failed to disconnect from MongoDB: %s\n", err)
		}
	}()

	collection := client.Database(dbName).Collection(opts.CollectionName)
	var actualRes output.ResultEvent
	err = collection.FindOne(ctx, map[string]interface{}{"request": res.Request}).Decode(&actualRes)
	if err != nil {
		return fmt.Errorf("failed to find document in MongoDB: %s", err)
	}

	if actualRes.Request != res.Request || actualRes.Response != res.Response {
		return fmt.Errorf("exported result does not match expected result: got %v, want %v", actualRes, res)
	}

	return nil
}
