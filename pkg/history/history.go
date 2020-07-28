package history

import (
	"encoding/json"

	"github.com/aquasecurity/trivy/internal/webcontext"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/boltdb/bolt"

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
			return err
		}

		date := wc.BeginTime.Format("20060102")
		b, err = b.CreateBucketIfNotExists([]byte(date))
		if err != nil {
			log.Logger.Debug("error when open date bucket: %s", err)
			return err
		}

		time := wc.BeginTime.Format("15:04:05")
		b.Put([]byte(time), formatRes(results))
		return nil
	})

	return nil
}

// 直接保存扫描结果太大，只保存 VulnerabilityID，用得时候再查
func formatRes(results report.Results) []byte {
	type vul struct {
		target          string
		typec           string
		VulnerabilityID string
	}

	length := len(results)
	vuls := make([]vul, length, 10)

	for i := range results {
		res := results[i]
		vuls[i].target = res.Target
		vuls[i].typec = res.Type
		vuls[i].VulnerabilityID = ""
		for j := range vuls[i].VulnerabilityID {
			vuls[i].VulnerabilityID += res.Vulnerabilities[j].VulnerabilityID + " || "
		}
	}

	res, err := json.MarshalIndent(vuls, "", "  ")
	if err != nil {
		log.Logger.Debug("error when formatRes: %s", err)
	}

	return res
}

func Get(cacheDir string, wc webcontext.WebContext) {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}

	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(historyBucket))
		if err != nil {
			log.Logger.Debug("error when open bucket: %s", err)
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			d := tx.Bucket(v)
			e := d.Cursor()
			for k1, v1 := e.First(); k1 != nil; k1, v1 = e.Next() {
				wc.Ictx.WriteString(string(v1) + " || ")
			}
		}
		return nil
	})
}

func Delete(cacheDir string, wc webcontext.WebContext) {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}

	db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(historyBucket))
		if err != nil {
			wc.Ictx.WriteString("err when Delete")
			return err
		}
		return nil
	})
}
