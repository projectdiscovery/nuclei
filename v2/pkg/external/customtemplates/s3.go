package customtemplates

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/projectdiscovery/gologger"
	nucleiConfig "github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var _ Provider = &customTemplateS3Bucket{}

type customTemplateS3Bucket struct {
	s3Client   *s3.Client
	bucketName string
	prefix     string
	Location   string
}

// Download retrieves all custom templates from s3 bucket
func (bk *customTemplateS3Bucket) Download(ctx context.Context) {
	downloadPath := filepath.Join(nucleiConfig.DefaultConfig.CustomS3TemplatesDirectory, bk.bucketName)

	s3Manager := manager.NewDownloader(bk.s3Client)
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
			if err := downloadToFile(s3Manager, downloadPath, bk.bucketName, aws.ToString(obj.Key)); err != nil {
				gologger.Error().Msgf("error downloading s3 bucket %s %s", bk.bucketName, err)
				return
			}
		}
	}
	gologger.Info().Msgf("AWS bucket %s was cloned successfully at %s", bk.bucketName, downloadPath)
}

// Update downloads custom templates from s3 bucket
func (bk *customTemplateS3Bucket) Update(ctx context.Context) {
	bk.Download(ctx)
}

// NewS3Providers returns a new instances of a s3 providers for downloading custom templates
func NewS3Providers(options *types.Options) ([]*customTemplateS3Bucket, error) {
	providers := []*customTemplateS3Bucket{}
	if options.AwsBucketName != "" && !options.AwsTemplateDisableDownload {
		s3c, err := getS3Client(context.TODO(), options.AwsAccessKey, options.AwsSecretKey, options.AwsRegion)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("error downloading s3 bucket %s", options.AwsBucketName)
		}
		ctBucket := &customTemplateS3Bucket{
			bucketName: options.AwsBucketName,
			s3Client:   s3c,
		}
		if strings.Contains(options.AwsBucketName, "/") {
			bPath := strings.SplitN(options.AwsBucketName, "/", 2)
			ctBucket.bucketName = bPath[0]
			ctBucket.prefix = bPath[1]
		}
		providers = append(providers, ctBucket)
	}
	return providers, nil
}

func downloadToFile(downloader *manager.Downloader, targetDirectory, bucket, key string) error {
	// Create the directories in the path
	file := filepath.Join(targetDirectory, key)
	// If empty dir in s3
	if stringsutil.HasSuffixI(key, "/") {
		return os.MkdirAll(file, 0775)
	}
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

func getS3Client(ctx context.Context, accessKey string, secretKey string, region string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}
