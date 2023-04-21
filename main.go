package main

import (
	http "github.com/bogdanfinn/fhttp"
	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	tokenController "helix/route"
	"html/template"
	"os"
)

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})
	r.GET("/", func(c *gin.Context) {
		// 解析HTML模板
		t, err := template.ParseFiles("templates/index.html")
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		// 填充模板变量
		vars := gin.H{
			"title": "Gin HTML Response",
		}
		// 将HTML响应写入HTTP响应
		err = t.Execute(c.Writer, vars)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
		}
	})
	r.POST("/token", tokenController.GetToken)
	gin.SetMode(gin.ReleaseMode)
	endless.ListenAndServe(os.Getenv("HOST")+":"+"8080", r)
}
