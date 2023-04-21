package tokenController

import (
	"github.com/gin-gonic/gin"
	"helix/service"
	"net/http"
)

var GetToken = func(c *gin.Context) {
	name := c.PostForm("username")
	email := c.PostForm("password")
	token, err := service.GetAccessToken(name, email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err})
		return
	}
	c.IndentedJSON(http.StatusOK, token)
}
