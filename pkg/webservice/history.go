package webservice

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	typesDetail "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/boltdb/bolt"
	uuid "github.com/iris-contrib/go.uuid"

	configup "github.com/aquasecurity/trivy/internal/config"
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

type scanHistory struct {
	Scanid      string `db:"scanid"`
	RequestType string
	Time        string
	Target      string
	From        string
	Fromid      string
	UserName    string `db:"username"`
}

const (
	vulsBucket = "vulnerability"
)

// SaveHis 保存历史记录
func SaveHis(results report.Results, wc configup.WebContext) error {
	// 插入 主表
	id, _ := uuid.NewV4()
	requestType := wc.Type
	time := wc.BeginTime
	target := wc.Target
	fromID := wc.FromID
	from := wc.From
	userID := wc.UserID
	_, err := MysqlDb.Exec("insert INTO history(scanid, type, time, target, fromwhere, fromid, userid) values(?,?,?,?,?,?,?)", id.String(), requestType, time, target, from, fromID, userID)
	if err != nil {
		fmt.Println("insert err:  ", err)
		return err
	}

	// 插入行表
	sqlStr := "insert into historyline(scanid, targetfile, type, vulnerabilityid, pkgname, installedversion, fixedversion, digest, diffid, severitysource) values"
	sqlStrData := ""
	sqlVal := []interface{}{}

	for i, resFile := range results {
		for j, resVul := range resFile.Vulnerabilities {
			if i != 0 || j != 0 {
				sqlStrData += ","
			}
			sqlStrData += "(?,?,?,?,?,?,?,?,?,?)"
			sqlVal = append(sqlVal, id.String(), resFile.Target, resFile.Type, resVul.VulnerabilityID, resVul.PkgName, resVul.InstalledVersion,
				resVul.FixedVersion, resVul.Layer.Digest, resVul.Layer.DiffID, resVul.SeveritySource)
		}
	}
	if sqlStrData == "" {
		return nil
	}
	sqlStr += sqlStrData
	stmt, _ := MysqlDb.Prepare(sqlStr)
	_, err = stmt.Exec(sqlVal...)
	if from == "timer" {
		if err != nil {
			MysqlDb.Exec("update timer set failtime=failtime+1 where timerid = ?", wc.FromID)
		}
		MysqlDb.Exec("update timer set successtime=successtime+1 where timerid = ?", wc.FromID)
	}
	if err != nil {
		fmt.Println("batch insert err:  ", err)
		return err
	}

	return nil
}

// GetHis 获取扫描历史列表
func GetHis(index string, size string) (interface{}, string, error) {
	indexInt, _ := strconv.Atoi(index)
	sizeInt, _ := strconv.Atoi(size)
	indexInt = (indexInt - 1) * sizeInt
	rows, err := MysqlDb.Query("select h.scanid, h.type, h.time, h.target, h.fromwhere, h.fromid, IFNULL(u.username,'') username from history h left join user u on h.userid = u.userid ORDER BY time desc LIMIT ?, ?", indexInt, size)
	historydatas := []scanHistory{}
	if err != nil {
		fmt.Println(err)
		return nil, "", err
	}
	for rows.Next() {
		var historydata scanHistory
		var scanTime time.Time
		err := rows.Scan(&historydata.Scanid, &historydata.RequestType, &scanTime, &historydata.Target, &historydata.From, &historydata.Fromid, &historydata.UserName)
		if historydata.UserName == "" {
			historydata.UserName = "定时器"
		}
		historydata.Time = scanTime.Format("2006-01-02 15:04:05")
		if err != nil {
			fmt.Println(err)
		}
		historydatas = append(historydatas, historydata)
	}

	num := "0"
	numRow := MysqlDb.QueryRow("select count(*) count from history")
	numRow.Scan(&num)

	return historydatas, num, nil
}

// GetHisDetail 获取历史扫描详情
func GetHisDetail(cacheDir string, scanid string) (interface{}, error) {
	// 从 MySQL 查历史
	var details report.Results
	rows, err := MysqlDb.Query("SELECT targetfile, `type`, vulnerabilityid, pkgname, installedversion, fixedversion, digest, diffid, severitysource FROM trivy.historyline WHERE scanid = ?", scanid)
	if err != nil {
		fmt.Println(err)
	}
	for rows.Next() {
		var detail report.Result
		var vul types.DetectedVulnerability
		rows.Scan(&detail.Target, &detail.Type, &vul.VulnerabilityID, &vul.PkgName, &vul.InstalledVersion, &vul.FixedVersion, &vul.Layer.Digest, &vul.Layer.DiffID, &vul.SeveritySource)
		ifAdd := false
		for i, existDetail := range details {
			if existDetail.Target == detail.Target && existDetail.Type == detail.Type {
				details[i].Vulnerabilities = append(existDetail.Vulnerabilities, vul)
				ifAdd = true
			}
		}
		if !ifAdd {
			detail.Vulnerabilities = append(detail.Vulnerabilities, vul)
			details = append(details, detail)
		}
	}

	// 从 bolt 查详情
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("exception on Open db: %s", err)
		return nil, err
	}
	defer db.Close()

	db.View(func(tx *bolt.Tx) error {
		vlusB := tx.Bucket([]byte(vulsBucket))

		for _, detail := range details {
			for i, vul := range detail.Vulnerabilities {
				value := vlusB.Get([]byte(vul.VulnerabilityID))
				var vulFromID typesDetail.Vulnerability
				json.Unmarshal(value, &vulFromID)
				detail.Vulnerabilities[i].Title = vulFromID.Title
				detail.Vulnerabilities[i].Description = vulFromID.Description
				detail.Vulnerabilities[i].Severity = vulFromID.Severity
				detail.Vulnerabilities[i].CweIDs = vulFromID.CweIDs
				detail.Vulnerabilities[i].VendorSeverity = vulFromID.VendorSeverity
				detail.Vulnerabilities[i].VendorVectors = vulFromID.VendorVectors
				detail.Vulnerabilities[i].CVSS = vulFromID.CVSS
				detail.Vulnerabilities[i].References = vulFromID.References
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return details, nil
}

// DeleteHis 删除扫描历史
func DeleteHis(scanid string) error {
	_, err := MysqlDb.Exec("delete from history where scanid=?", scanid)
	_, err = MysqlDb.Exec("delete from historyline where scanid=?", scanid)
	return err
}
