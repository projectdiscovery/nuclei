package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Catalog manages the AWS S3 template catalog
type Catalog struct {
	svc client
}

// client interface abstracts S3 connections
type client interface {
	getAllKeys() ([]string, error)
	downloadKey(name string) (io.ReadCloser, error)
	setBucket(bucket string)
}

type s3svc struct {
	client *s3.Client
	bucket string
}

// NewCatalog creates a new AWS Catalog object given a required S3 bucket name and optional configurations. If
// no configurations to set AWS keys are provided then environment variables will be used to obtain AWS credentials.
func NewCatalog(bucket string, configurations ...func(*Catalog) error) (Catalog, error) {
	var c Catalog

	for _, configuration := range configurations {
		err := configuration(&c)
		if err != nil {
			return c, err
		}
	}

	if c.svc == nil {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return c, err
		}

		c.svc = &s3svc{
			client: s3.NewFromConfig(cfg),
		}
	}
	c.svc.setBucket(bucket)

	return c, nil
}

// WithAWSKeys enables explicitly setting the AWS access key, secret key and region
func WithAWSKeys(accessKey, secretKey, region string) func(*Catalog) error {
	return func(c *Catalog) error {
		cfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
			config.WithRegion(region))
		if err != nil {
			return err
		}

		c.svc = &s3svc{
			client: s3.NewFromConfig(cfg),
			bucket: "",
		}

		return nil
	}
}

// OpenFile downloads a file from S3 and returns the contents as an io.ReadCloser
func (c Catalog) OpenFile(filename string) (io.ReadCloser, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	return c.svc.downloadKey(filename)
}

// GetTemplatePath looks for a target string performing a simple substring check
// against all S3 keys. If the input includes a wildcard (*) it is removed.
func (c Catalog) GetTemplatePath(target string) ([]string, error) {
	target = strings.ReplaceAll(target, "*", "")

	keys, err := c.svc.getAllKeys()
	if err != nil {
		return nil, err
	}

	var matches []string
	for _, key := range keys {
		if strings.Contains(key, target) {
			matches = append(matches, key)
		}
	}

	return matches, nil
}

// GetTemplatesPath returns all templates from S3
func (c Catalog) GetTemplatesPath(definitions []string) ([]string, map[string]error) {
	keys, err := c.svc.getAllKeys()
	if err != nil {
		// necessary to implement the Catalog interface
		return nil, map[string]error{"aws": err}
	}

	return keys, nil
}

// ResolvePath gets a full S3 key given the first param. If the second parameter is
// provided it tries to find paths relative to the second path.
func (c Catalog) ResolvePath(templateName, second string) (string, error) {
	keys, err := c.svc.getAllKeys()
	if err != nil {
		return "", err
	}

	// if c second path is given, it's c folder and we join the two and check against keys
	if second != "" {
		// Note: Do not replace `path` with `filepath` since filepath is aware of Os path separator
		// and we only see `/` in s3 paths changing it to filepath cause build fail and other errors
		target := path.Join(path.Dir(second), templateName)
		for _, key := range keys {
			if key == target {
				return key, nil
			}
		}
	}

	// check if templateName is already an absolute path to c key
	for _, key := range keys {
		if key == templateName {
			return templateName, nil
		}
	}

	return "", fmt.Errorf("no such path found: %s%s for keys: %v", second, templateName, keys)
}

func (s *s3svc) getAllKeys() ([]string, error) {
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: &s.bucket,
	})

	var keys []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (s *s3svc) downloadKey(name string) (io.ReadCloser, error) {
	downloader := manager.NewDownloader(s.client)
	buf := manager.NewWriteAtBuffer([]byte{})
	_, err := downloader.Download(context.TODO(), buf, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(name),
	})
	if err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func (s *s3svc) setBucket(bucket string) {
	s.bucket = bucket
}
