package history

import (
	"encoding/json"

	"github.com/aquasecurity/trivy/internal/webcontext"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/boltdb/bolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

var historyBucket = "history"

func Save(cacheDir string, results report.Results, wc webcontext.WebContext) error {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}

	db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(historyBucket))
		if err != nil {
			log.Logger.Debug("error when open bucket: %s", err)
		}

		date := wc.BeginTime.Format("20060102")
		b, err = b.CreateBucketIfNotExists([]byte(date))
		if err != nil {
			log.Logger.Debug("error when open date bucket: %s", err)
		}

		time := wc.BeginTime.Format("15:04:05")
		output, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return xerrors.Errorf("failed to marshal json: %w", err)
		}
		b.Put([]byte(time), []byte(string(output)))
		for i := range results {
			b.Put([]byte(results[i].Type), []byte(results[i].Target))
		}
		return nil
	})

	return nil
}
