package main

import (
	"github.com/gin-gonic/gin"
	"github.com/yourusername/blockchain-edu-backend/internal/api"
	"github.com/yourusername/blockchain-edu-backend/internal/auth"
	"github.com/yourusername/blockchain-edu-backend/internal/config"
	"github.com/yourusername/blockchain-edu-backend/internal/database"
	"log"
)

func main() {
	config.LoadConfig()

	if err := database.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	handler, err := api.NewHandler()
	if err != nil {
		log.Fatalf("Failed to create API handler: %v", err)
	}

	r := gin.Default()

	// 公开路由
	r.POST("/register", handler.RegisterUser)
	r.POST("/login", handler.Login) // 需要实现登录处理函数

	// 需要认证的路由
	authorized := r.Group("/")
	authorized.Use(auth.AuthMiddleware())
	{
		authorized.GET("/user/:userID/score", handler.GetUserScore)
		authorized.PUT("/user/:userID/score", handler.UpdateUserScore)
		authorized.DELETE("/user/:userID", handler.DeleteUser)
	}

	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
