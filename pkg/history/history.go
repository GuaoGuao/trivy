package history

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/trivy/internal/webcontext"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/boltdb/bolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

type vul struct {
	Target          string
	Typec           string
	VulnerabilityID string
}

const historyBucket = "history"
const vulsBucket = "vulnerability"

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
	length := len(results)
	vuls := make([]vul, length, 10)

	for i := range results {
		res := results[i]
		vuls[i].Target = res.Target
		vuls[i].Typec = res.Type
		vuls[i].VulnerabilityID = ""
		for j := range res.Vulnerabilities {
			vuls[i].VulnerabilityID += res.Vulnerabilities[j].VulnerabilityID
			if j != len(res.Vulnerabilities)-1 {
				vuls[i].VulnerabilityID += " || "
			}
		}
	}

	res, err := json.Marshal(vuls)
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
		data := make([]vul, 10, 10)
		b := tx.Bucket([]byte(historyBucket))
		if err != nil {
			log.Logger.Debug("error when open bucket: %s", err)
		}
		c := b.Cursor()

		log.Logger.Debug("================logger1================")

		// 循环每一天
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			d := b.Bucket(k)
			e := d.Cursor()

			// 循环一天的每一次
			for k1, v1 := e.First(); k1 != nil; k1, v1 = e.Next() {
				err := json.Unmarshal(v1, &data)
				log.Logger.Debug("================logger2================")
				if err != nil {
					log.Logger.Debug("error when unmarshal json: %s", err)
					return nil
				}
				// 查出来的结果转成 report.Result 再输出
				var results report.Results

				// 循环每一种 Type
				for _, vul := range data {
					result := report.Result{
						Target:          vul.Target,
						Type:            vul.Typec,
						Vulnerabilities: []types.DetectedVulnerability{},
					}
					idArr := strings.Split(vul.VulnerabilityID, " || ")
					log.Logger.Debug("================logger3================")

					// 循环每个 漏洞
					for _, id := range idArr {
						vlusB := tx.Bucket([]byte(vulsBucket))
						value := vlusB.Get([]byte(id))
						var vulFromID types.DetectedVulnerability
						json.Unmarshal(value, &vulFromID)
						vulFromID.VulnerabilityID = id
						result.Vulnerabilities = append(result.Vulnerabilities, vulFromID)
					}

					results = append(results, result)
					output, err := json.MarshalIndent(results, "", "  ")
					if err != nil {
						return xerrors.Errorf("failed to marshal json: %w", err)
					}
					wc.Ictx.WriteString(string(output))
				}
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
