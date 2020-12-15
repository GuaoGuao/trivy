package webservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/aquasecurity/trivy/internal/artifact/config"
	configup "github.com/aquasecurity/trivy/internal/config"
	"github.com/aquasecurity/trivy/internal/webservice/scanhandler"
	"github.com/aquasecurity/trivy/pkg/webservice"
	"github.com/kataras/iris"
	"github.com/kataras/iris/sessions"
	"github.com/urfave/cli/v2"
)

type pageRes struct {
	Results   interface{}
	PageTotal string
}

var wc configup.WebContext
var sess = sessions.New(sessions.Config{Cookie: "secret"})

// Run web 服务
func Run(cliCtx *cli.Context) error {
	// webservice.TimerAdd("* * * * *", "123", "1`23")
	// 初始化数据库连接
	webservice.Init()

	wc.Ctx = cliCtx
	wc.Webapp = iris.New()
	wc.Webapp.Use(Cors)

	wc.Webapp.Post("/scanner", typeHandler)
	wc.Webapp.Get("/listimages", listimages)

	wc.Webapp.Get("/history/getlist", getHistory)
	wc.Webapp.Get("/history/getdetail", getHistoryDetail)
	wc.Webapp.Get("/history/delete", deleteHistory)

	wc.Webapp.Get("/user/login", login)
	wc.Webapp.Get("/user/logout", logout)
	wc.Webapp.Get("/user/list", userList)
	wc.Webapp.Get("/user/add", userAdd)
	wc.Webapp.Get("/user/delete", userDelete)

	wc.Webapp.Get("/timer/get", timerGet)
	wc.Webapp.Post("/timer/add", timerAdd)
	wc.Webapp.Get("/timer/delete", timerDelete)

	wc.Webapp.Run(iris.Addr(":9327"), iris.WithoutServerError(iris.ErrServerClosed))

	return nil
}

// Cors 处理跨域
func Cors(ctx iris.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	if ctx.Request().Method == "OPTIONS" {
		ctx.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS")
		ctx.Header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
		ctx.StatusCode(204)
		return
	}
	ctx.Next()
}

func typeHandler(context iris.Context) {
	flag, userID := checkSession(context)
	if !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context
	wc.UserID = userID
	wc.FromID = userID
	wc.From = "user"

	var params configup.Param
	if err := context.ReadJSON(&params); err != nil {
		panic(err.Error())
	}
	wc.Type = params.Type
	wc.Target = params.Name
	results, err := scanhandler.ScanHandler(wc, params)
	webservice.SaveHis(results, wc)

	if err != nil {
		respWriter(wc.Ictx, "FAIL", err)
		return
	}
	respWriter(wc.Ictx, "SUCCESS", results)
}

func listimages(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	cmd := exec.Command("docker", "image", "list")
	cmd.Stdin = bytes.NewBuffer(nil)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}
	respWriter(context, "SUCCESS", out.String())
}

func getHistory(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	pageIndex := context.URLParam("pageIndex")
	pageSize := context.URLParam("pageSize")
	results, pageTotal, err := webservice.GetHis(pageIndex, pageSize)
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}
	var result pageRes
	result.Results = results
	result.PageTotal = pageTotal

	respWriter(context, "SUCCESS", result)
}

func getHistoryDetail(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	c, err := config.New(wc.Ctx)
	if err != nil {
		fmt.Printf("error when create new config: %v", err)
		respWriter(context, "FAIL", err)
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	result, err := webservice.GetHisDetail(c.CacheDir, context.URLParam("scanId"))
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}
	respWriter(context, "SUCCESS", result)
}

func deleteHistory(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}

	scanID := context.URLParam("scanId")
	err := webservice.DeleteHis(scanID)
	if err != nil {
		respWriter(context, "FAIL", err)
	} else {
		respWriter(context, "SUCCESS", "删除成功")
	}
}

func login(context iris.Context) {
	session := sess.Start(context)

	c, err := config.New(wc.Ctx)
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	userID, err := webservice.Login(c.CacheDir, wc)
	if err != nil {
		respWriter(context, "LOGINFAIL", err)
		return
	}

	session.Set("authenticated", true)
	session.Set("userId", userID)
	respWriter(context, "SUCCESS", "登录成功")
}

func logout(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	session := sess.Start(context)
	session.Set("authenticated", false)
	respWriter(context, "SUCCESS", "登出成功")
}

func userList(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	pageIndex := context.URLParam("pageIndex")
	pageSize := context.URLParam("pageSize")
	results, pageTotal, err := webservice.GetUsers(pageIndex, pageSize)
	if err != nil {
		respWriter(context, "FAIL", err)
	}

	var result pageRes
	result.Results = results
	result.PageTotal = pageTotal

	respWriter(context, "SUCCESS", result)
}

func userAdd(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	err := webservice.AddUser(wc)
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}

	respWriter(context, "SUCCESS", "添加成功")
}

func userDelete(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	userID := context.URLParam("userId")
	err := webservice.DeleteUser(userID)
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}

	respWriter(context, "SUCCESS", "删除成功")
}

func timerGet(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	pageIndex := context.URLParam("pageIndex")
	pageSize := context.URLParam("pageSize")
	results, pageTotal, err := webservice.TimerGet(pageIndex, pageSize)
	if err != nil {
		respWriter(context, "FAIL", err)
	}

	var result pageRes
	result.Results = results
	result.PageTotal = pageTotal

	respWriter(context, "SUCCESS", result)
}

func timerAdd(context iris.Context) {
	flag, userID := checkSession(context)
	if !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context
	wc.UserID = userID

	var params configup.Param
	if err := context.ReadJSON(&params); err != nil {
		panic(err.Error())
	}
	wc.Type = params.Type

	err := webservice.TimerAdd(wc, params)
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}

	respWriter(context, "SUCCESS", "定时任务添加成功")
}

func timerDelete(context iris.Context) {
	flag, userID := checkSession(context)
	if !flag {
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context
	wc.UserID = userID
	timerID := context.URLParam("timerId")
	cronID := context.URLParam("cronId")

	err := webservice.TimerDelete(wc, timerID, cronID)
	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}

	respWriter(context, "SUCCESS", "定时任务添加成功")
}

// 验证会话
func checkSession(context iris.Context) (bool, string) {
	if auth, _ := sess.Start(context).GetBoolean("authenticated"); !auth {
		respWriter(context, "UNLOGIN", nil)
		return false, ""
	}
	useID := sess.Start(context).GetString("userId")
	return true, useID
	// return true, "123456789"
}

// 写入返回
func respWriter(context iris.Context, status string, data interface{}) {
	res := configup.Response{
		Status: configup.Codes[status],
		Msg:    configup.Text[status],
		Data:   data,
	}

	jsonRes, err := json.Marshal(res)
	if err != nil {
		fmt.Printf("err when marshal res json: %v", err)
		res.Status = configup.Codes["FAIL"]
		res.Msg = configup.Text["FAIL"]
		res.Data = err
	}

	context.WriteString(string(jsonRes))
}
