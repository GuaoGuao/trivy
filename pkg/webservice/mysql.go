package webservice

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type History struct {
	ScanId int `db:"scanid"`
}

var MysqlDb *sql.DB
var MysqlDbErr error

const (
	// USER_NAME = "root321"
	// PASS_WORD = "lihang136464"
	// HOST      = "39.78.246.215"
	// PORT      = "3306"
	// DATABASE  = "trivy"
	// CHARSET   = "utf8"
	USER_NAME = "root"
	PASS_WORD = "lihang321"
	HOST      = "localhost"
	PORT      = "3306"
	DATABASE  = "trivy"
	CHARSET   = "utf8"
)

// 初始化链接
func Init() {
	dbDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&loc=%s&parseTime=true", USER_NAME, PASS_WORD, HOST, PORT, DATABASE, CHARSET, url.QueryEscape("Asia/Shanghai"))

	// 打开连接失败
	MysqlDb, MysqlDbErr = sql.Open("mysql", dbDSN)
	//defer MysqlDb.Close();
	if MysqlDbErr != nil {
		log.Println("dbDSN: " + dbDSN)
		panic("数据源配置不正确: " + MysqlDbErr.Error())
	}

	// 最大连接数
	MysqlDb.SetMaxOpenConns(100)
	// 闲置连接数
	MysqlDb.SetMaxIdleConns(20)
	// 最大连接周期
	MysqlDb.SetConnMaxLifetime(100 * time.Second)

	if MysqlDbErr = MysqlDb.Ping(); nil != MysqlDbErr {
		panic("数据库链接失败: " + MysqlDbErr.Error())
	}

}
