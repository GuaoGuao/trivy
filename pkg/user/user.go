package user

import (
	"time"

	"encoding/json"

	"github.com/aquasecurity/trivy/internal/config"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/boltdb/bolt"
	uuid "github.com/iris-contrib/go.uuid"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

type user struct {
	Id         []byte
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

func Login(cacheDir string, wc config.WebContext) bool {
	res := false
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}
	defer db.Close()

	var u = user{
		Id:       []byte(wc.Ictx.URLParam("id")),
		Username: wc.Ictx.URLParam("username"),
	}

	db.Update(func(tx *bolt.Tx) error {
		top, _ := tx.CreateBucketIfNotExists([]byte(userBucket))
		heads, _ := top.CreateBucketIfNotExists([]byte(userHeadBucket))
		lines, _ := top.CreateBucketIfNotExists([]byte(userLineBucket))
		passwordInput := wc.Ictx.URLParam("password")

		u.getUserFromName(heads, lines)

		if passwordInput == u.Password {
			res = true
		}
		return nil
	})

	return res
}

func Add(cacheDir string, wc config.WebContext) error {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}
	defer db.Close()

	//获取get请求所携带的参数
	username := wc.Ictx.URLParam("username")
	wc.Webapp.Logger().Info(username)
	password := wc.Ictx.URLParam("password")
	wc.Webapp.Logger().Info(password)
	id, _ := uuid.NewV4()
	var user = user{
		Id:         id.Bytes(),
		Username:   username,
		Password:   password,
		Type:       "super",
		Createtime: time.Now().Format("20060102150405"),
	}

	db.Update(func(tx *bolt.Tx) error {
		top, _ := tx.CreateBucketIfNotExists([]byte(userBucket))
		heads, _ := top.CreateBucketIfNotExists([]byte(userHeadBucket))
		lines, _ := top.CreateBucketIfNotExists([]byte(userLineBucket))
		detail, _ := lines.CreateBucketIfNotExists(id.Bytes())
		putstring(heads, user.Username, string(user.Id))
		putstring(detail, "id", string(user.Id))
		putstring(detail, "username", user.Username)
		putstring(detail, "password", user.Password)
		putstring(detail, "type", user.Type)
		putstring(detail, "createtime", user.Createtime)
		return nil
	})

	return nil
}

func Delete(cacheDir string, wc config.WebContext) {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}
	defer db.Close()

	var u = user{
		Id:       []byte(wc.Ictx.URLParam("id")),
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

func Get(cacheDir string, wc config.WebContext) {
	dbPath := db.Path(cacheDir)
	db, err := bolt.Open(dbPath, 0666, nil)
	if err != nil {
		log.Logger.Debug("exception on Open db: %s", err)
	}
	defer db.Close()

	db.View(func(tx *bolt.Tx) error {
		top, _ := tx.CreateBucketIfNotExists([]byte(userBucket))
		lines, _ := top.CreateBucketIfNotExists([]byte(userLineBucket))

		c := lines.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			detail := lines.Bucket([]byte(k))
			var u = user{
				Id:         detail.Get([]byte("id")),
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

func (u *user) getUserFromName(heads *bolt.Bucket, lines *bolt.Bucket) {
	// 默认从id取，没有id就先从头表取
	if len(u.Id) == 0 {
		id := heads.Get([]byte(u.Username))
		u.Id = id
	}
	detail := lines.Bucket(u.Id)
	u.Username = string(detail.Get([]byte("username")))
	u.Password = string(detail.Get([]byte("password")))
	u.Type = string(detail.Get([]byte("type")))
	u.Createtime = string(detail.Get([]byte("createtime")))
}

func putstring(bucket *bolt.Bucket, key string, value string) {
	bucket.Put([]byte(key), []byte(value))
}
