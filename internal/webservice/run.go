package webservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/aquasecurity/trivy/internal/artifact"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	configup "github.com/aquasecurity/trivy/internal/config"
	"github.com/aquasecurity/trivy/pkg/history"
	"github.com/aquasecurity/trivy/pkg/user"
	"github.com/kataras/iris"
	"github.com/kataras/iris/sessions"
	"github.com/urfave/cli/v2"
)

var wc configup.WebContext
var sess = sessions.New(sessions.Config{Cookie: "secret"})

func Run(cliCtx *cli.Context) error {
	wc.Ctx = cliCtx
	wc.Webapp = iris.New()
	wc.Webapp.Use(Cors)

	wc.Webapp.Post("/scanner", typeHandler)
	wc.Webapp.Get("/listimages", listimages)

	wc.Webapp.Get("/history/get", getHistory)
	wc.Webapp.Post("/history/delete", deleteHistory)

	wc.Webapp.Get("/user/login", login)
	wc.Webapp.Get("/user/logout", logout)
	wc.Webapp.Get("/user/add", userAdd)
	wc.Webapp.Get("/user/delete", userDelete)
	wc.Webapp.Get("/user/get", userGet)

	wc.Webapp.Run(iris.Addr(":9327"), iris.WithoutServerError(iris.ErrServerClosed))

	return nil
}

// Cors
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
	path := context.Path()
	wc.Webapp.Logger().Info(path)
	wc.BeginTime = time.Now()
	wc.Ictx = context
	//获取get请求所携带的参数
	scanType := context.URLParam("type")
	wc.Webapp.Logger().Info(scanType)

	name := context.URLParam("name")
	wc.Webapp.Logger().Info(name)

	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
	}

	if scanType == "image" {
		// initialize config
		if err = c.Init(true); err != nil {
			context.WriteString("failed to initialize options: " + err.Error())
			return
		}
		c.Target = name
		c.ExitCode = 1

		if c.Input != "" {
			// scan tar file
			artifact.RunWeb(c, artifact.ArchiveScanner, wc)
		}

		results, err := artifact.RunWeb(c, artifact.DockerScanner, wc)
		respWriter(context, results, err)
	} else {
		// initialize config
		if err = c.Init(false); err != nil {
			context.WriteString("failed to initialize options: " + err.Error())
			return
		}

		c.Target = name
		c.ExitCode = 1
		results, err := artifact.RunWeb(c, artifact.RepositoryScanner, wc)
		respWriter(context, results, err)
	}
}

func listimages(context iris.Context) {
	cmd := exec.Command("docker", "image", "list")
	cmd.Stdin = bytes.NewBuffer(nil)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()

	respWriter(context, out, err)
}

func getHistory(context iris.Context) {
	c, err := config.New(wc.Ctx)
	if err != nil {
		fmt.Printf("err when create new config: %v", err)
		respWriter(context, nil, err)
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	history.Get(c.CacheDir, wc)
}

func deleteHistory(context iris.Context) {
	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	history.Delete(c.CacheDir, wc)
}

func login(context iris.Context) {
	session := sess.Start(context)

	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	flag := user.Login(c.CacheDir, wc)
	if !flag {
		return
	}

	session.Set("authenticated", true)
}

func logout(context iris.Context) {
	session := sess.Start(context)
	session.Set("authenticated", false)
}

func userAdd(context iris.Context) {
	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	user.Add(c.CacheDir, wc)
}

func userDelete(context iris.Context) {
	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	user.Delete(c.CacheDir, wc)
}

func userGet(context iris.Context) {
	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
	}
	wc.BeginTime = time.Now()
	wc.Ictx = context

	user.Get(c.CacheDir, wc)
}

// 验证会话
func checkSession(context iris.Context) (bool, error) {
	if auth, _ := sess.Start(context).GetBoolean("authenticated"); !auth {
		res := configup.Response{
			Status: configup.Codes["SUCCESS"],
			Msg:    "未登录，请登录后再试",
		}

		jsonRes, err := json.Marshal(res)
		if err != nil {
			fmt.Printf("err when marshal res json: %v", err)
			res.Status = configup.Codes["JSONERROR"]
			res.Msg = "JSON 转换错误"
			res.Data = err
		}

		context.WriteString(string(jsonRes))
		return false, nil
	}
	return true, nil
}

// 写入返回
func respWriter(context iris.Context, data interface{}, err error) {
	res := configup.Response{
		Status: "000",
		Msg:    "Success",
		Data:   data,
	}

	if err != nil {
		res.Status = configup.Codes["FAIL"]
		res.Msg = "服务器异常，请稍后重试"
		res.Data = err
	}

	jsonRes, err := json.Marshal(res)
	if err != nil {
		fmt.Printf("err when marshal res json: %v", err)
		res.Status = configup.Codes["JSONERROR"]
		res.Msg = "JSON 转换错误"
		res.Data = err
	}

	context.WriteString(string(jsonRes))
}
