package config

import (
	"time"

	"github.com/kataras/iris"
	"github.com/urfave/cli/v2"
)

type WebContext struct {
	Webapp    *iris.Application
	Ctx       *cli.Context
	BeginTime time.Time
	Ictx      iris.Context
}

type Response struct {
	Status string
	Msg    string
	Data   interface{}
}

// 000 成功， 001 失败, 011 未登录, 012 json 转换错误
var Codes = map[string]string{
	"SUCCESS":   "000",
	"FAIL":      "001",
	"UNLOGIN":   "011",
	"JSONERROR": "012",
}
