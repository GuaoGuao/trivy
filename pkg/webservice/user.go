package webservice

import (
	"crypto/md5"
	"errors"
	"fmt"
	"time"

	"encoding/hex"

	"github.com/aquasecurity/trivy/internal/config"
	"github.com/boltdb/bolt"
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
	fmt.Println([]byte(passWord))
	myMd5.Write([]byte(salt))
	fmt.Println([]byte(salt))
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

func AddUser(cacheDir string, wc config.WebContext) error {
	userID, _ := uuid.NewV4()
	userName := wc.Ictx.URLParam("username")
	passWord := wc.Ictx.URLParam("password")
	salt, _ := uuid.NewV4()
	createTime := time.Now()
	loginTime := time.Now()
	userType := wc.Ictx.URLParam("usertype")

	// md5 加密
	myMd5 := md5.New()
	saltString := hex.EncodeToString(salt.Bytes())
	myMd5.Write([]byte(passWord))
	fmt.Println([]byte(passWord))
	myMd5.Write([]byte(saltString))
	fmt.Println([]byte(saltString))
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

func DeleteUser(cacheDir string, wc config.WebContext) error {
	userId := wc.Ictx.URLParam("userid")
	_, err := MysqlDb.Exec("delete from user where userid = ?", userId)

	if err != nil {
		fmt.Println("err when deleteuser", err)
		return err
	}

	return nil
}

func GetUsers(cacheDir string, wc config.WebContext) (interface{}, error) {
	rows, err := MysqlDb.Query("SELECT userid, username, createtime, logintime, usertype from user")
	if err != nil {
		fmt.Println("error when getuser: ", err)
		return nil, err
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
		rows.Scan(&auser.Userid, &auser.Username, &auser.CreateTime, &auser.Logintime, &auser.Usertype)
		users = append(users, auser)
	}
	return users, nil
}

func (u *user) getUserFromName(heads *bolt.Bucket, lines *bolt.Bucket) error {
	// 默认从id取，没有id就先从头表取
	if len(u.Id) == 0 {
		id := heads.Get([]byte(u.Username))
		if id == nil {
			fmt.Printf("数据库中没有这个账号")
			return errors.New("账户或密码错误，请检查")
		}
		u.Id = string(id)
	}
	detail := lines.Bucket([]byte(u.Id))
	u.Username = string(detail.Get([]byte("username")))
	u.Password = string(detail.Get([]byte("password")))
	u.Type = string(detail.Get([]byte("type")))
	u.Createtime = string(detail.Get([]byte("createtime")))

	return nil
}

func putstring(bucket *bolt.Bucket, key string, value string) {
	bucket.Put([]byte(key), []byte(value))
}
