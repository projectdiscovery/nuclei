package customtemplates

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var _ Provider = &customTemplateAzureBlob{}

type customTemplateAzureBlob struct {
	azureBlobClient *azblob.Client
	containerName   string
}

// NewAzureProviders creates a new Azure Blob Storage provider for downloading custom templates
func NewAzureProviders(options *types.Options) ([]*customTemplateAzureBlob, error) {
	providers := []*customTemplateAzureBlob{}
	if options.AzureContainerName != "" && !options.AzureTemplateDisableDownload {
		// Establish a connection to Azure and build a client object with which to download templates from Azure Blob Storage
		azClient, err := getAzureBlobClient(options.AzureTenantID, options.AzureClientID, options.AzureClientSecret, options.AzureServiceURL)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("Error establishing Azure Blob client for %s", options.AzureContainerName)
		}

		// Create a new Azure Blob Storage container object
		azTemplateContainer := &customTemplateAzureBlob{
			azureBlobClient: azClient,
			containerName:   options.AzureContainerName,
		}

		// Add the Azure Blob Storage container object to the list of custom templates
		providers = append(providers, azTemplateContainer)
	}
	return providers, nil
}

func getAzureBlobClient(tenantID string, clientID string, clientSecret string, serviceURL string) (*azblob.Client, error) {
	// Create an Azure credential using the provided credentials
	credentials, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		gologger.Error().Msgf("Invalid Azure credentials: %v", err)
		return nil, err
	}

	// Create a client to manage Azure Blob Storage
	client, err := azblob.NewClient(serviceURL, credentials, nil)
	if err != nil {
		gologger.Error().Msgf("Error creating Azure Blob client: %v", err)
		return nil, err
	}

	return client, nil
}

func (bk *customTemplateAzureBlob) Download(ctx context.Context) {
	// Set an incrementer for the number of templates downloaded
	var templatesDownloaded = 0

	// Define the local path to which the templates will be downloaded
	downloadPath := filepath.Join(config.DefaultConfig.CustomAzureTemplatesDirectory, bk.containerName)

	// Get the list of all templates from the container
	pager := bk.azureBlobClient.NewListBlobsFlatPager(bk.containerName, &azblob.ListBlobsFlatOptions{
		// Don't include previous versions of the templates if versioning is enabled on the container
		Include: azblob.ListBlobsInclude{Snapshots: false, Versions: false},
	})

	// Loop through the list of blobs in the container and determine if they should be added to the list of templates
	// to be returned, and subsequently downloaded
	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		if err != nil {
			gologger.Error().Msgf("Error listing templates in Azure Blob container: %v", err)
			return
		}

		for _, blob := range resp.Segment.BlobItems {
			// If the blob is a .yaml download the file to the local filesystem
			if strings.HasSuffix(*blob.Name, ".yaml") {
				// Download the template to the local filesystem at the downloadPath
				err := downloadTemplate(bk.azureBlobClient, bk.containerName, *blob.Name, filepath.Join(downloadPath, *blob.Name), ctx)
				if err != nil {
					gologger.Error().Msgf("Error downloading template: %v", err)
				} else {
					// Increment the number of templates downloaded
					templatesDownloaded++
				}
			}
		}
	}

	// Log the number of templates downloaded
	gologger.Info().Msgf("Downloaded %d templates from Azure Blob Storage container '%s' to: %s", templatesDownloaded, bk.containerName, downloadPath)
}

// Update updates the templates from the Azure Blob Storage container to the local filesystem. This is effectively a
// wrapper of the Download function which downloads of all templates from the container and doesn't manage a
// differential update.
func (bk *customTemplateAzureBlob) Update(ctx context.Context) {
	// Treat the update as a download of all templates from the container
	bk.Download(ctx)
}

// downloadTemplate downloads a template from the Azure Blob Storage container to the local filesystem with the provided
// blob path and outputPath.
func downloadTemplate(client *azblob.Client, containerName string, path string, outputPath string, ctx context.Context) error {
	// Download the blob as a byte stream
	get, err := client.DownloadStream(ctx, containerName, path, nil)
	if err != nil {
		gologger.Error().Msgf("Error downloading template: %v", err)
		return err
	}

	downloadedData := bytes.Buffer{}
	retryReader := get.NewRetryReader(ctx, &azblob.RetryReaderOptions{})
	_, err = downloadedData.ReadFrom(retryReader)
	if err != nil {
		gologger.Error().Msgf("Error reading template: %v", err)
		return err
	}

	err = retryReader.Close()
	if err != nil {
		gologger.Error().Msgf("Error closing template filestream: %v", err)
		return err
	}

	// Ensure the directory exists
	err = os.MkdirAll(filepath.Dir(outputPath), 0755)
	if err != nil {
		gologger.Error().Msgf("Error creating directory: %v", err)
		return err
	}

	// Write the downloaded template to the local filesystem at the outputPath with the filename of the blob name
	err = os.WriteFile(outputPath, downloadedData.Bytes(), 0644)

	return err
}
