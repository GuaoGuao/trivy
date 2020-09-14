package scanhandler

import (
	"fmt"

	"github.com/aquasecurity/trivy/internal/artifact"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	configup "github.com/aquasecurity/trivy/internal/config"
	"github.com/aquasecurity/trivy/pkg/report"
)

func ScanHandler(wc configup.WebContext, params configup.Param) (report.Results, error) {
	c, err := config.New(wc.Ctx)
	if err != nil {
		wc.Ictx.WriteString(err.Error())
		return nil, err
	}
	var results report.Results

	if params.Type == "image" {
		// initialize config
		if err = c.Init(true); err != nil {
			wc.Ictx.WriteString("failed to initialize options: " + err.Error())
			fmt.Printf("failed to initialize options: " + err.Error())
			return nil, err
		}
		c.Target = params.Name
		c.ExitCode = 1

		if c.Input != "" {
			// scan tar file
			artifact.RunWeb(c, artifact.ArchiveScanner, wc)
		}

		results, err = artifact.RunWeb(c, artifact.DockerScanner, wc)
	} else if params.Type == "repo" {
		// initialize config
		if err = c.Init(false); err != nil {
			wc.Ictx.WriteString("failed to initialize options: " + err.Error())
			fmt.Printf("failed to initialize options: " + err.Error())
			return nil, err
		}

		c.Target = params.Name
		c.ExitCode = 1
		results, err = artifact.RunWeb(c, artifact.RepositoryScanner, wc)
	} else if params.Type == "fs" {
		// initialize config
		if err = c.Init(false); err != nil {
			wc.Ictx.WriteString("failed to initialize options: " + err.Error())
			fmt.Printf("failed to initialize options: " + err.Error())
			return nil, err
		}

		c.Target = params.Name
		c.ExitCode = 1
		results, err = artifact.RunWeb(c, artifact.FilesystemScanner, wc)
	}

	return results, err
}
