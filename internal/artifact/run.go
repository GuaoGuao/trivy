package artifact

import (
	"context"
	"encoding/json"
	l "log"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/internal/operation"
	tdb "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/history"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/kataras/iris"
)

type InitializeScanner func(context.Context, string, cache.ArtifactCache, cache.LocalArtifactCache, time.Duration) (
	scanner.Scanner, func(), error)

// RunWeb 调用 web 接口时用的，需要返回结果
func RunWeb(c config.Config, initializeScanner InitializeScanner, context iris.Context) error {
	results, err := subrun(c, initializeScanner)
	if err != nil {
		return err
	}

	history.Save(c.CacheDir, results)

	if err = report.WriteResults(c.Format, c.Output, results, c.Template, c.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	if c.ExitCode != 0 {
		// TODO 当前仅支持输出 JSON
		output, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return xerrors.Errorf("failed to marshal json: %w", err)
		}

		tdb.WriteResults(output)

		context.WriteString(string(output))

	}
	return nil
}

func run(c config.Config, initializeScanner InitializeScanner) error {
	results, err := subrun(c, initializeScanner)
	if err != nil {
		return err
	}

	if err = report.WriteResults(c.Format, c.Output, results, c.Template, c.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
	return nil
}

func subrun(c config.Config, initializeScanner InitializeScanner) (report.Results, error) {
	if err := log.InitLogger(c.Debug, c.Quiet); err != nil {
		l.Fatal(err)
	}

	// configure cache dir
	utils.SetCacheDir(c.CacheDir)
	cacheClient, err := cache.NewFSCache(c.CacheDir)
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	defer cacheClient.Close()

	cacheOperation := operation.NewCache(cacheClient)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		return nil, cacheOperation.Reset()
	}
	if c.ClearCache {
		return nil, cacheOperation.ClearImages()
	}

	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err = operation.DownloadDB(c.AppVersion, c.CacheDir, noProgress, c.Light, c.SkipUpdate); err != nil {
		return nil, err
	}

	if c.DownloadDBOnly {
		return nil, nil
	}

	if err = db.Init(c.CacheDir); err != nil {
		return nil, xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	defer db.Close()

	target := c.Target
	if c.Input != "" {
		target = c.Input
	}

	ctx := context.Background()
	scanner, cleanup, err := initializeScanner(ctx, target, cacheClient, cacheClient, c.Timeout)
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType:            c.VulnType,
		ScanRemovedPackages: c.ScanRemovedPkgs, // this is valid only for image subcommand
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	results, err := scanner.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return nil, xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
		results[i].Vulnerabilities = vulnClient.Filter(results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile)
	}
	return results, nil
}
