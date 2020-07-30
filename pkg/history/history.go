package history

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/internal/config"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/boltdb/bolt"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

type vul struct {
	Target          string
	Typec           string
	VulnerabilityID string
}

type dateResult struct {
	Time    string
	Results report.Results
}

type dateResults []dateResult

const (
	historyBucket = "history"
	vulsBucket    = "vulnerability"
)

func Save(cacheDir string, results report.Results, wc config.WebContext) error {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("exception on Open db: %s", err)
	}
	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(historyBucket))
		if err != nil {
			fmt.Printf("error when open bucket: %s", err)
			return err
		}

		date := wc.BeginTime.Format("20060102")
		b, err = b.CreateBucketIfNotExists([]byte(date))
		if err != nil {
			fmt.Printf("error when open date bucket: %s", err)
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
		fmt.Printf("error when formatRes: %s", err)
	}

	return res
}

func Get(cacheDir string, wc config.WebContext) (interface{}, error) {
	var historys dateResults
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("exception on Open db: %s", err)
		return nil, err
	}
	defer db.Close()

	db.View(func(tx *bolt.Tx) error {
		data := make([]vul, 10, 10)
		b := tx.Bucket([]byte(historyBucket))
		c := b.Cursor()

		// 循环每一天
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			d := b.Bucket(k)
			e := d.Cursor()

			// 循环一天的每一次
			for k1, v1 := e.First(); k1 != nil; k1, v1 = e.Next() {
				err = json.Unmarshal(v1, &data)
				if err != nil {
					fmt.Printf("error when unmarshal json: %s", err)
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
				}

				historys = append(historys, dateResult{
					Time:    string(k) + string(k1),
					Results: results,
				})
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return historys, nil
}

func Delete(cacheDir string, wc config.WebContext) error {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("exception on Open db: %s", err)
		return err
	}
	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		err = tx.DeleteBucket([]byte(historyBucket))
		if err != nil {
			fmt.Printf("err when Delete: %s", err)
			return err
		}
		return nil
	})
	return err
}
