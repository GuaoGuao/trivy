package webservice

import (
	"errors"
	"fmt"
	"time"

	"encoding/json"

	"github.com/aquasecurity/trivy/internal/config"
	"github.com/boltdb/bolt"
	uuid "github.com/iris-contrib/go.uuid"

	"github.com/aquasecurity/trivy-db/pkg/db"
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
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("failed to open db: " + err.Error())
		return "", err
	}
	defer db.Close()

	var u = user{
		Id:       string(wc.Ictx.URLParam("id")),
		Username: wc.Ictx.URLParam("username"),
	}

	db.Update(func(tx *bolt.Tx) error {
		top, _ := tx.CreateBucketIfNotExists([]byte(userBucket))
		heads, _ := top.CreateBucketIfNotExists([]byte(userHeadBucket))
		lines, _ := top.CreateBucketIfNotExists([]byte(userLineBucket))
		passwordInput := wc.Ictx.URLParam("password")

		err = u.getUserFromName(heads, lines)
		if err != nil {
			return err
		}

		if passwordInput != u.Password {
			err = errors.New("密码错误")
		}
		return nil
	})

	return "", err
}

func AddUser(cacheDir string, wc config.WebContext) error {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("exception on Open db: %s", err)
	}
	defer db.Close()

	//获取get请求所携带的参数
	username := wc.Ictx.URLParam("username")
	wc.Webapp.Logger().Info(username)
	password := wc.Ictx.URLParam("password")
	wc.Webapp.Logger().Info(password)
	id, _ := uuid.NewV4()
	var user = user{
		Id:         id.String(),
		Username:   username,
		Password:   password,
		Type:       "super",
		Createtime: time.Now().Format("20060102150405"),
	}

	db.Update(func(tx *bolt.Tx) error {
		top, _ := tx.CreateBucketIfNotExists([]byte(userBucket))
		heads, _ := top.CreateBucketIfNotExists([]byte(userHeadBucket))
		lines, _ := top.CreateBucketIfNotExists([]byte(userLineBucket))
		detail, _ := lines.CreateBucketIfNotExists([]byte(user.Id))
		putstring(heads, user.Username, user.Id)
		putstring(detail, "id", user.Id)
		putstring(detail, "username", user.Username)
		putstring(detail, "password", user.Password)
		putstring(detail, "type", user.Type)
		putstring(detail, "createtime", user.Createtime)
		return nil
	})

	return nil
}

func DeleteUser(cacheDir string, wc config.WebContext) {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("exception on Open db: %s", err)
	}
	defer db.Close()

	var u = user{
		Id:       string(wc.Ictx.URLParam("id")),
		Username: wc.Ictx.URLParam("username"),
	}

	db.Update(func(tx *bolt.Tx) error {
		top, _ := tx.CreateBucketIfNotExists([]byte(userBucket))
		heads, _ := top.CreateBucketIfNotExists([]byte(userHeadBucket))
		lines, _ := top.CreateBucketIfNotExists([]byte(userLineBucket))
		u.getUserFromName(heads, lines)
		err = heads.DeleteBucket([]byte(u.Username))
		err = lines.DeleteBucket([]byte(u.Id))
		if err != nil {
			wc.Ictx.WriteString("err when Delete")
			return err
		}
		return nil
	})
}

func GetUser(cacheDir string, wc config.WebContext) {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		fmt.Printf("exception on Open db: %s", err)
	}
	defer db.Close()

	db.View(func(tx *bolt.Tx) error {
		top, _ := tx.CreateBucketIfNotExists([]byte(userBucket))
		lines, _ := top.CreateBucketIfNotExists([]byte(userLineBucket))

		c := lines.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			detail := lines.Bucket([]byte(k))
			var u = user{
				Id:         string(detail.Get([]byte("id"))),
				Username:   string(detail.Get([]byte("username"))),
				Password:   string(detail.Get([]byte("password"))),
				Type:       string(detail.Get([]byte("type"))),
				Createtime: string(detail.Get([]byte("createtime"))),
			}
			outputs, _ := json.Marshal(u)
			wc.Ictx.WriteString(string(outputs))
		}

		return nil
	})
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
