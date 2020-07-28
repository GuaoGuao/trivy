package history

import (
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/boltdb/bolt"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

var historyBucket = "history"

func Save(cacheDir string, results report.Results) error {
	dbPath := db.Path(cacheDir)
	// file, err := os.Create(dbPath)
	// if err != nil {
	// 	log.Logger.Debug("There is no valid metadata file: %s", err)
	// }
	// log.Logger.Debug(file)

	log.Logger.Warn("=============lihang cacheDir=================")
	log.Logger.Warn(cacheDir)

	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}

	db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(historyBucket))
		if err != nil {
			log.Logger.Debug("error when open bucket: %s", err)
		}
		for i := range results {
			// b.Put([]byte("a"), []byte("42"))
			log.Logger.Warn("=============lihang key-value=================")
			log.Logger.Warn(cacheDir)
			b.Put([]byte(results[i].Type), []byte(results[i].Target))
		}
		return nil
	})

	return nil
}
