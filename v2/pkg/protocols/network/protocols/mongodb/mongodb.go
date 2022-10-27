package mongodb

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// ConnectWithCredentials connects to a server with credentials
func ConnectWithCredentials(host, username, password string, port, timeout int) (bool, error) {
	url := fmt.Sprintf("mongodb://%s:%s@%s:%d/%s", username, password, host, port, "test")

	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(url).SetTimeout(time.Duration(timeout)*time.Second))
	if err != nil {
		return false, errors.Wrap(err, "could not connect to mongodb")
	}
	defer func() {
		_ = client.Disconnect(context.Background())
	}()

	if err = client.Ping(context.Background(), readpref.Primary()); err != nil {
		return false, errors.Wrap(err, "could not ping mongodb")
	}
	return true, nil
}
