package main

import (
	"fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/api"
	"github.com/cynic-1/blockchain-edu-backend/internal/auth"
	"github.com/cynic-1/blockchain-edu-backend/internal/config"
	"github.com/cynic-1/blockchain-edu-backend/internal/database"
	"github.com/gin-gonic/gin"
	"log"
)

func main() {
	config.LoadConfig("./config.yaml")

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
	r.POST("/login", handler.Login)

	// 需要认证的路由
	authorized := r.Group("/")
	authorized.Use(auth.AuthMiddleware())
	{
		authorized.GET("/user/:userID/score", handler.GetUserScore)
		authorized.DELETE("/user/:userID", handler.DeleteUser)                   // 添加删除用户路由
		authorized.POST("/user/:userID/change-password", handler.ChangePassword) // 添加修改密码路由

		// 容器相关的路由
		authorized.POST("/container", handler.CreateContainer)
		authorized.POST("/container/start", handler.StartContainer)
		authorized.POST("/container/stop", handler.StopContainer)
		authorized.DELETE("/container", handler.RemoveContainer)
	}

	// 管理员路由
	admin := r.Group("/admin")
	admin.Use(auth.AuthMiddleware(), auth.AdminMiddleware())
	{
		admin.POST("/users/bulk-create", handler.BulkCreateUsers)
		admin.GET("/students", handler.GetAllStudents)

		// 管理员也可以删除用户和修改用户密码
		admin.DELETE("/user/:userID", handler.DeleteUser)
		admin.POST("/user/:userID/change-password", handler.AdminChangePassword)
	}

	if err := r.Run(fmt.Sprintf(":%d", config.AppConfig.Server.Port)); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}