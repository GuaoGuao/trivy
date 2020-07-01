package webservice

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"

	"github.com/aquasecurity/trivy/internal/artifact"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/emicklei/go-restful"
	"github.com/kataras/iris"
	"github.com/urfave/cli/v2"
)

var webapp *iris.Application
var ctx *cli.Context

func Run(cliCtx *cli.Context) error {
	ctx = cliCtx
	webapp = iris.New()

	webapp.Get("/scanner", typeHandler)

	webapp.Run(iris.Addr(":9327"), iris.WithoutServerError(iris.ErrServerClosed))
	return nil
}

func typeHandler(context iris.Context) {
	path := context.Path()
	webapp.Logger().Info(path)
	//获取get请求所携带的参数
	scanType := context.URLParam("type")
	webapp.Logger().Info(scanType)

	name := context.URLParam("name")
	webapp.Logger().Info(name)

	c, err := config.New(ctx)
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

		if c.Input != "" {
			// scan tar file
			artifact.RunWeb(c, artifact.ArchiveScanner, context)
		}

		artifact.RunWeb(c, artifact.DockerScanner, context)
	} else {
		// initialize config
		if err = c.Init(false); err != nil {
			context.WriteString("failed to initialize options: " + err.Error())
			return
		}

		c.Target = name
		artifact.RunWeb(c, artifact.RepositoryScanner, context)
	}
}

// RunRestful 第一个版本
func RunRestful() {
	wsContainer := restful.NewContainer()

	ws := new(restful.WebService)
	ws.Route(ws.GET("/").To(doScan))
	wsContainer.Add(ws)

	// Add container filter to enable CORS
	cors := restful.CrossOriginResourceSharing{
		ExposeHeaders:  []string{"X-My-Header"},
		AllowedHeaders: []string{"Content-Type", "Accept"},
		AllowedMethods: []string{"GET", "POST"},
		CookiesAllowed: false,
		Container:      wsContainer,
	}
	wsContainer.Filter(cors.Filter)

	wsContainer.Filter(wsContainer.OPTIONSFilter)

	log.Print("start listening on localhost:9328")
	server := &http.Server{Addr: ":9328", Handler: wsContainer}
	log.Fatal(server.ListenAndServe())
}

func doScan(req *restful.Request, resp *restful.Response) {
	cmd := exec.Command("trivy", "repo", "https://github.com/knqyf263/trivy-ci-test")
	in := bytes.NewBuffer(nil)
	cmd.Stdin = in
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Command finished with error: %v", err)
		io.WriteString(resp.ResponseWriter, err.Error())
	}
	io.WriteString(resp.ResponseWriter, out.String())
}
