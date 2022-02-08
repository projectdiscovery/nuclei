package client

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetTemplates(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := TemplatesService{Client: client}
	resp, err := svc.GetTemplates(GetTemplatesRequest{
		Folder: "nuclei-templates",
		Search: "CVE-2000-0114.yaml",
	})
	require.NoError(t, err, "could not get templates")
	require.Greater(t, len(resp), 0)
}

func TestAddTemplate(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := TemplatesService{Client: client}
	resp, err := svc.AddTemplate(AddTemplateRequest{
		Folder: "nuclei-templates",
		Path:   "cves/2000/CVE-2000-0116.yaml",
	})
	fmt.Println("......")
	if err == nil {
		require.Greater(t, resp, int64(0))
	}
}

func TestUpdateTemplate(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := TemplatesService{Client: client}
	err := svc.UpdateTemplate(UpdateTemplateRequest{
		Path: "cves/2000/CVE-2000-0116.yaml",
	})
	require.NoError(t, err, "could not update template")

}

func TestDeleteTemplate(t *testing.T) {

	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := TemplatesService{Client: client}
	err := svc.DeleteTemplate(DeleteTemplateRequest{
		Path: "cves/2000/CVE-2000-0116.yaml",
	})
	require.NoError(t, err, "could not delete template")
}

func TestGetTemplateRaw(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := TemplatesService{Client: client}
	resp, err := svc.GetTemplateRaw("test.yaml")
	require.NoError(t, err, "could not get raw template")
	require.NotEmpty(t, resp)

}

func TestExecuteTemplate(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := TemplatesService{Client: client}
	_, err := svc.ExecuteTemplate(ExecuteTemplateRequest{
		Path:   "technologies/ibm/ibm-http-server.yaml",
		Target: "example.com",
	})
	require.NoError(t, err, "could not execute template")
}
