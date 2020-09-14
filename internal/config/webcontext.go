package config

import (
	"time"

	"github.com/kataras/iris"
	"github.com/urfave/cli/v2"
)

// 获取post请求所携带的参数 typehandler
type Param struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Interval string `json:"interval"`
}

type WebContext struct {
	Webapp    *iris.Application
	Ctx       *cli.Context
	BeginTime time.Time
	Ictx      iris.Context
	Type      string
	Target    string
	UserID    string
	FromID    string
	From      string
}

type Response struct {
	Status string
	Msg    string
	Data   interface{}
}

// Codes 返回里只有能够显示的状态和文字
// 000 成功， 001 失败, 011 未登录
var Codes = map[string]string{
	"SUCCESS":   "000",
	"FAIL":      "001",
	"UNLOGIN":   "011",
	"LOGINFAIL": "012",
}

var Text = map[string]string{
	"SUCCESS":   "请求成功",
	"FAIL":      "请求失败，请稍后重试",
	"UNLOGIN":   "未登录，请登录后再试",
	"LOGINFAIL": "登录失败，请检查账号和密码",
}
