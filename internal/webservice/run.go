package webservice

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/aquasecurity/trivy/internal/artifact"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	configup "github.com/aquasecurity/trivy/internal/config"
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
	path := context.Path()
	wc.Webapp.Logger().Info(path)
	wc.BeginTime = time.Now()
	wc.Ictx = context
	wc.UserID = userID

	//获取post请求所携带的参数
	type param struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	var params param
	if err := context.ReadJSON(&params); err != nil {
		panic(err.Error())
	}
	wc.Type = params.Type

	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
	}

	if params.Type == "image" {
		// initialize config
		if err = c.Init(true); err != nil {
			context.WriteString("failed to initialize options: " + err.Error())
			fmt.Printf("failed to initialize options: " + err.Error())
			return
		}
		c.Target = params.Name
		c.ExitCode = 1

		if c.Input != "" {
			// scan tar file
			artifact.RunWeb(c, artifact.ArchiveScanner, wc)
		}

		results, err := artifact.RunWeb(c, artifact.DockerScanner, wc)

		if err != nil {
			respWriter(context, "FAIL", err)
			return
		}
		respWriter(context, "SUCCESS", results)
	} else {
		// initialize config
		if err = c.Init(false); err != nil {
			context.WriteString("failed to initialize options: " + err.Error())
			fmt.Printf("failed to initialize options: " + err.Error())
			return
		}

		c.Target = params.Name
		c.ExitCode = 1
		results, err := artifact.RunWeb(c, artifact.RepositoryScanner, wc)

		if err != nil {
			respWriter(context, "FAIL", err)
			return
		}
		respWriter(context, "SUCCESS", results)
	}
}

func listimages(context iris.Context) {
	if flag, _ := checkSession(context); !flag {
		return
	}
	cmd := exec.Command("docker", "image", "list")
	cmd.Stdin = bytes.NewBuffer(nil)
	var out bytes.Buffer
	cmd.Stdout = &out

	fmt.Println(out)
	err := cmd.Run()
	fmt.Println(out)
	fmt.Println(hex.EncodeToString(out.Bytes()))
	fmt.Println(out.String())

	if err != nil {
		respWriter(context, "FAIL", err)
		return
	}
	respWriter(context, "SUCCESS", out)
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

// 验证会话
func checkSession(context iris.Context) (bool, string) {
	// if auth, _ := sess.Start(context).GetBoolean("authenticated"); !auth {
	// 	respWriter(context, "UNLOGIN", nil)
	// 	return false, ""
	// }
	// return true, sess.Start(context).GetString("userID")
	return true, "123456789"
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
