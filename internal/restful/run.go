package restful

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"

	"github.com/emicklei/go-restful"
)

func TestRest() {
	ws := new(restful.WebService)
	ws.Route(ws.GET("/").To(doScan))
	restful.Add(ws)
	log.Fatal(http.ListenAndServe(":8080", nil))
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
