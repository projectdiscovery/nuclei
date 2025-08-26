package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/mongo"
	"github.com/testcontainers/testcontainers-go"
	mongocontainer "github.com/testcontainers/testcontainers-go/modules/mongodb"

	osutil "github.com/projectdiscovery/utils/os"
	mongoclient "go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

const (
	dbName  = "test"
	dbImage = "mongo:8"
)

var exportersTestCases = []TestCaseInfo{
	{Path: "exporters/mongo", TestCase: &mongoExporter{}, DisableOn: func() bool {
		return osutil.IsWindows() || osutil.IsOSX()
	}},
}

type mongoExporter struct{}

func (m *mongoExporter) Execute(filepath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Start a MongoDB container
	mongodbContainer, err := mongocontainer.Run(ctx, dbImage)
	defer func() {
		if err := testcontainers.TerminateContainer(mongodbContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	connString, err := mongodbContainer.ConnectionString(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection string for MongoDB container: %s", err)
	}
	connString = connString + dbName

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
