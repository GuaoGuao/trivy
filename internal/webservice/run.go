package webservice

import (
	"bytes"
	"fmt"
	"os/exec"
	"time"

	"github.com/aquasecurity/trivy/internal/artifact"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/internal/webcontext"
	"github.com/aquasecurity/trivy/pkg/history"
	"github.com/kataras/iris"
	"github.com/urfave/cli/v2"
)

var wc webcontext.WebContext

func Run(cliCtx *cli.Context) error {
	wc.Ctx = cliCtx
	wc.Webapp = iris.New()
	wc.Webapp.Use(Cors)

	wc.Webapp.Get("/scanner", typeHandler)
	wc.Webapp.Get("/listimages", listimages)
	wc.Webapp.Get("/history/get", getHistory)
	wc.Webapp.Get("/history/delete", deleteHistory)

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

		artifact.RunWeb(c, artifact.DockerScanner, wc)
	} else {
		// initialize config
		if err = c.Init(false); err != nil {
			context.WriteString("failed to initialize options: " + err.Error())
			return
		}

		c.Target = name
		c.ExitCode = 1
		artifact.RunWeb(c, artifact.RepositoryScanner, wc)
	}
}

func listimages(context iris.Context) {
	cmd := exec.Command("docker", "image", "list")
	cmd.Stdin = bytes.NewBuffer(nil)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Command finished with error: %v", err)
		context.WriteString(string(err.Error()))
	}
	context.WriteString(out.String())
}

func getHistory(context iris.Context) {
	c, err := config.New(wc.Ctx)
	if err != nil {
		context.WriteString(err.Error())
		return
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

// RunRestful 第一个版本
// func RunRestful() {
// 	wsContainer := restful.NewContainer()

// 	ws := new(restful.WebService)
// 	ws.Route(ws.GET("/").To(doScan))
// 	wsContainer.Add(ws)

// 	// Add container filter to enable CORS
// 	cors := restful.CrossOriginResourceSharing{
// 		ExposeHeaders:  []string{"X-My-Header"},
// 		AllowedHeaders: []string{"Content-Type", "Accept"},
// 		AllowedMethods: []string{"GET", "POST"},
// 		CookiesAllowed: false,
// 		Container:      wsContainer,
// 	}
// 	wsContainer.Filter(cors.Filter)

// 	wsContainer.Filter(wsContainer.OPTIONSFilter)

// 	log.Print("start listening on localhost:9328")
// 	server := &http.Server{Addr: ":9328", Handler: wsContainer}
// 	log.Fatal(server.ListenAndServe())
// }

// func doScan(req *restful.Request, resp *restful.Response) {
// 	cmd := exec.Command("trivy", "repo", "https://github.com/knqyf263/trivy-ci-test")
// 	in := bytes.NewBuffer(nil)
// 	cmd.Stdin = in
// 	var out bytes.Buffer
// 	cmd.Stdout = &out
// 	err := cmd.Run()
// 	if err != nil {
// 		fmt.Printf("Command finished with error: %v", err)
// 		io.WriteString(resp.ResponseWriter, err.Error())
// 	}
// 	io.WriteString(resp.ResponseWriter, out.String())
// }
