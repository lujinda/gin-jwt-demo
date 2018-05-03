package main

import (
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gin-gonic/gin"
)

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const SECRET_KEY = "Hello"

func JWTAuthorization(c *gin.Context) {
	if c.Request.URL.Path == "/login" {
		return
	}

	token, err := request.ParseFromRequest(c.Request, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		})
	if err != nil {
		c.String(http.StatusUnauthorized, "Unauthorized access to this resource")
		c.Abort()

	} else {
		if token.Valid {
			c.Set("token", token)
			c.Next()

		} else {
			c.String(http.StatusUnauthorized, "Token is not valid")
			c.Abort()
		}
	}
}

func LoginHandler(c *gin.Context) {
	credentials := UserCredentials{}
	c.BindJSON(&credentials)
	if !(credentials.Username == "tuxpy" && credentials.Password == "1#P") {
		c.String(http.StatusForbidden, "Invalid credentials")
		return
	}

	claims := make(jwt.MapClaims)
	claims["exp"] = (time.Now().Add(time.Minute)).Unix()
	claims["iat"] = time.Now().Unix()
	claims["username"] = credentials.Username
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(SECRET_KEY))
	if err != nil {
		c.String(http.StatusInternalServerError, "Error while signing the token")
		return
	}
	c.JSON(http.StatusOK, struct {
		Token string `json:"token"`
	}{tokenString})
}

func HelloHandler(c *gin.Context) {
	token := c.MustGet("token").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	c.String(http.StatusOK, fmt.Sprintf("Hello %v", claims["username"]))
}

func main() {
	engine := gin.Default()
	engine.Use(JWTAuthorization)
	engine.POST("/login", LoginHandler)
	engine.GET("/hello", HelloHandler)
	engine.Run(":8080")
}
