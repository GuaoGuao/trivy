package webservice

import (
	"crypto/md5"
	"errors"
	"fmt"
	"strconv"
	"time"

	"encoding/hex"

	"github.com/aquasecurity/trivy/internal/config"
	uuid "github.com/iris-contrib/go.uuid"
)

type user struct {
	Id         string
	Username   string
	Password   string
	Type       string
	Createtime string
}

const (
	userBucket     = "users"
	userHeadBucket = "head"
	userLineBucket = "line"
)

func Login(cacheDir string, wc config.WebContext) (string, error) {
	userName := wc.Ictx.URLParam("username")
	passWord := wc.Ictx.URLParam("password")

	row := MysqlDb.QueryRow("select userid, salt, password from user where username=?", userName)
	var userId, salt, passwordR string
	row.Scan(&userId, &salt, &passwordR)

	myMd5 := md5.New()
	myMd5.Write([]byte(passWord))
	myMd5.Write([]byte(salt))
	passWordMd5 := myMd5.Sum(nil)
	passWord = hex.EncodeToString(passWordMd5)

	if passWord != passwordR {
		return "", errors.New("密码有误，请确认后重试")
	}

	// 更新登录时间
	_, err := MysqlDb.Exec("update user set logintime = ? where userid = ?", time.Now(), userId)
	if err != nil {
		fmt.Println("error when update logintime:  ", err)
		return "", err
	}

	return userId, nil
}

func AddUser(wc config.WebContext) error {
	userID, _ := uuid.NewV4()
	userName := wc.Ictx.URLParam("name")
	passWord := wc.Ictx.URLParam("password")
	salt, _ := uuid.NewV4()
	createTime := time.Now()
	loginTime := time.Now()
	userType := wc.Ictx.URLParam("type")
	if userType == "" {
		userType = "user"
	}

	// md5 加密
	myMd5 := md5.New()
	saltString := hex.EncodeToString(salt.Bytes())
	myMd5.Write([]byte(passWord))
	myMd5.Write([]byte(saltString))
	passWordMd5 := myMd5.Sum(nil)
	passWord = hex.EncodeToString(passWordMd5)

	_, err := MysqlDb.Exec("insert into user (userid, username, password, salt, createtime, logintime, usertype) values (?,?,?,?,?,?,?)",
		userID, userName, passWord, saltString, createTime, loginTime, userType)

	if err != nil {
		fmt.Printf("exception on insert user db: %s", err)
		return err
	}
	return nil
}

func DeleteUser(userId string) error {
	_, err := MysqlDb.Exec("delete from user where userid = ?", userId)

	if err != nil {
		fmt.Println("err when deleteuser", err)
		return err
	}

	return nil
}

func GetUsers(index string, size string) (interface{}, string, error) {
	indexInt, _ := strconv.Atoi(index)
	sizeInt, _ := strconv.Atoi(size)
	indexInt = (indexInt - 1) * sizeInt
	rows, err := MysqlDb.Query("SELECT userid, username, createtime, logintime, usertype from user ORDER BY logintime desc LIMIT ?, ?", indexInt, sizeInt)
	if err != nil {
		fmt.Println("error when getuser: ", err)
		return nil, "", err
	}
	type user struct {
		Userid     string
		Username   string
		CreateTime string
		Logintime  string
		Usertype   string
	}
	users := []user{}
	for rows.Next() {
		var auser user
		var ctime time.Time
		var ltime time.Time
		rows.Scan(&auser.Userid, &auser.Username, &ctime, &ltime, &auser.Usertype)
		auser.CreateTime = ctime.Format("2006-01-02 15:04:05")
		auser.Logintime = ltime.Format("2006-01-02 15:04:05")
		users = append(users, auser)
	}

	num := "0"
	numRow := MysqlDb.QueryRow("SELECT count(*) count from user")
	numRow.Scan(&num)

	return users, num, nil
}
