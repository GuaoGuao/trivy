package webcontext

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
