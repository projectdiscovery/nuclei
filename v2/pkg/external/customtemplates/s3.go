package customtemplates

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/projectdiscovery/gologger"
)

type customTemplateS3Bucket struct {
	s3Client   *s3.Client
	bucketName string
	prefix     string
}

// download custom templates from s3 bucket
func (bk *customTemplateS3Bucket) Download(location string, ctx context.Context) {
	downloadPath := filepath.Join(location, customS3TemplateDirectory, bk.bucketName)

	manager := manager.NewDownloader(bk.s3Client)
	paginator := s3.NewListObjectsV2Paginator(bk.s3Client, &s3.ListObjectsV2Input{
		Bucket: &bk.bucketName,
		Prefix: &bk.prefix,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			gologger.Error().Msgf("error downloading s3 bucket %s %s", bk.bucketName, err)
			return
		}
		for _, obj := range page.Contents {
			if err := downloadToFile(manager, downloadPath, bk.bucketName, aws.ToString(obj.Key)); err != nil {
				gologger.Error().Msgf("error downloading s3 bucket %s %s", bk.bucketName, err)
				return
			}
		}
	}
	gologger.Info().Msgf("AWS bucket %s successfully cloned successfully at %s", bk.bucketName, downloadPath)
}

// download custom templates from s3 bucket
func (bk *customTemplateS3Bucket) Update(location string, ctx context.Context) {
	bk.Download(location, ctx)
}

func downloadToFile(downloader *manager.Downloader, targetDirectory, bucket, key string) error {
	// Create the directories in the path
	file := filepath.Join(targetDirectory, key)
	if err := os.MkdirAll(filepath.Dir(file), 0775); err != nil {
		return err
	}

	// Set up the local file
	fd, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fd.Close()

	// Download the file using the AWS SDK for Go
	_, err = downloader.Download(context.TODO(), fd, &s3.GetObjectInput{Bucket: &bucket, Key: &key})

	return err
}

func getS3Client(ctx context.Context, acccessKey, secretKey, region string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(acccessKey, secretKey, "")), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}
