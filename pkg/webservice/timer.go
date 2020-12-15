package webservice

import (
	"fmt"
	"strconv"
	"time"

	"github.com/aquasecurity/trivy/internal/config"
	"github.com/aquasecurity/trivy/internal/webservice/scanhandler"
	uuid "github.com/iris-contrib/go.uuid"
	cron "github.com/robfig/cron/v3"
)

var C = cron.New()

func TimerGet(index string, size string) (interface{}, string, error) {
	indexInt, _ := strconv.Atoi(index)
	sizeInt, _ := strconv.Atoi(size)
	indexInt = (indexInt - 1) * sizeInt
	rows, err := MysqlDb.Query("SELECT timerid, entryid, target, type, t.createtime, lasttime, u.username, successtime, failtime from timer t left join user u on t.userid=u.userid ORDER BY t.createtime desc LIMIT ?, ?", indexInt, sizeInt)
	if err != nil {
		fmt.Println("error when TimerGet: ", err)
		return nil, "", err
	}
	type timer struct {
		Timerid     string
		Entryid     string
		Target      string
		Scantype    string
		Createtime  string
		Lasttime    string
		Userid      string
		Successtime string
		Failtime    string
	}
	timers := []timer{}
	for rows.Next() {
		var atimer timer
		var ctime time.Time
		var ltime time.Time
		rows.Scan(&atimer.Timerid, &atimer.Entryid, &atimer.Target, &atimer.Scantype, &ctime, &ltime, &atimer.Userid, &atimer.Successtime, &atimer.Failtime)
		atimer.Createtime = ctime.Format("2006-01-02 15:04:05")
		atimer.Lasttime = ltime.Format("2006-01-02 15:04:05")
		timers = append(timers, atimer)
	}

	num := "0"
	numRow := MysqlDb.QueryRow("SELECT count(*) count from timer")
	numRow.Scan(&num)

	return timers, num, nil
}

func TimerAdd(wc config.WebContext, param config.Param) error {
	timerID, _ := uuid.NewV4()
	entryID, _ := C.AddFunc(param.Interval, func() {
		wc.FromID = timerID.String()
		wc.From = "timer"
		wc.UserID = ""
		results, err := scanhandler.ScanHandler(wc, param)
		if err != nil {
			SaveHis(results, wc)
		}
		SaveHis(results, wc)
	})
	createtime := time.Now()
	userid := wc.UserID

	_, err := MysqlDb.Exec("insert into timer (timerid, entryid, target, type, createtime, lasttime, userid, successtime, failtime) values (?,?,?,?,?,?,?,?,?)",
		timerID, entryID, param.Name, param.Type, createtime, createtime, userid, 0, 0)
	if err != nil {
		fmt.Println("err when timer insert")
		fmt.Println(err)
	}
	C.Start()

	return nil
}

func TimerDelete(wc config.WebContext, timerID string, cronID string) error {
	var cronIDEntry cron.EntryID
	cronIDInt, _ := strconv.Atoi(cronID)
	cronIDEntry = cron.EntryID(cronIDInt)
	C.Remove(cronIDEntry)

	_, err := MysqlDb.Exec("delete from timer where timerid = ?", timerID)
	if err != nil {
		fmt.Println("err when timer delete")
		fmt.Println(err)
		return err
	}
	return nil
}
