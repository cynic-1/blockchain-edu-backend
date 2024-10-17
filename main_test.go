package blockchain_edu_backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	_ "fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/models"
	_ "io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cynic-1/blockchain-edu-backend/internal/api"
	"github.com/cynic-1/blockchain-edu-backend/internal/auth"
	"github.com/cynic-1/blockchain-edu-backend/internal/config"
	"github.com/cynic-1/blockchain-edu-backend/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var router *gin.Engine

func TestMain(m *testing.M) {
	// 设置测试环境
	gin.SetMode(gin.TestMode)
	config.LoadConfig("./config.yaml")
	if err := database.InitDB(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// 测试数据库连接
	if err := database.DB.Raw("SELECT 1").Error; err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Successfully connected to database")

	// 清理数据库
	cleanupDatabase()

	// 创建路由
	router = setupRouter()

	// 运行测试
	code := m.Run()

	// 清理测试数据
	cleanupTestData()

	os.Exit(code)
}

func cleanupDatabase() {
	database.DB.Exec("TRUNCATE TABLE users RESTART IDENTITY")
}

func setupRouter() *gin.Engine {
	r := gin.Default()
	handler, _ := api.NewHandler()

	r.POST("/register", handler.RegisterUser)
	r.POST("/login", handler.Login)

	authorized := r.Group("/")
	authorized.Use(auth.AuthMiddleware())
	{
		authorized.GET("/user/:userID/score", handler.GetUserScore)
		authorized.DELETE("/user/:userID", handler.DeleteUser)
		authorized.POST("/user/:userID/change-password", handler.ChangePassword)

		authorized.POST("/container", handler.CreateContainer)
		authorized.POST("/container/start", handler.StartContainer)
		authorized.POST("/container/stop", handler.StopContainer)
		authorized.DELETE("/container", handler.RemoveContainer)
	}

	admin := r.Group("/admin")
	admin.Use(auth.AuthMiddleware(), auth.AdminMiddleware())
	{
		admin.POST("/users/bulk-create", handler.BulkCreateUsers)
		admin.GET("/students", handler.GetAllStudents)
		admin.DELETE("/user/:userID", handler.DeleteUser)
		admin.POST("/user/:userID/change-password", handler.ChangePassword)
	}

	return r
}

func TestAllAPIs(t *testing.T) {
	fmt.Println("Starting TestAllAPIs")
	fmt.Println("Cleaning up database...")
	cleanupDatabase()
	fmt.Println("Database cleaned up")

	// 1. 注册普通用户
	w := performRequest(router, "POST", "/register", `{"user_id":"testuser","password":"testpass","class":"testclass","grade":"testgrade"}`)
	assert.Equal(t, 201, w.Code, "Failed to register user: %s", w.Body.String())

	// 打印所有用户
	var users []models.User
	database.DB.Find(&users)
	log.Printf("All users after registration: %+v", users)

	// 确认用户已创建
	var user models.User
	result := database.DB.Where("user_id = ?", "testuser").First(&user)
	assert.NoError(t, result.Error, "Failed to find created user")
	assert.Equal(t, "testuser", user.UserID)

	// 2. 注册管理员
	w = performRequest(router, "POST", "/register", `{"user_id":"admin","password":"adminpass","class":"admin","grade":"admin","is_admin":true}`)
	assert.Equal(t, 201, w.Code, "Failed to register admin: %s", w.Body.String())

	// 确认管理员已创建
	var admin models.User
	result = database.DB.Where("user_id = ?", "admin").First(&admin)
	assert.NoError(t, result.Error, "Failed to find created admin")
	assert.Equal(t, "admin", admin.UserID)
	assert.True(t, admin.IsAdmin)

	// 打印所有用户
	var allUsers []models.User
	database.DB.Find(&allUsers)
	log.Printf("All users before login: %+v", allUsers)

	// 3. 登录普通用户
	w = performRequest(router, "POST", "/login", `{"user_id":"testuser","password":"testpass"}`)
	assert.Equal(t, 200, w.Code, "Failed to login user: %s", w.Body.String())
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	userToken := response["token"]

	log.Printf("User token: %+v", userToken)

	// 4. 登录管理员
	w = performRequest(router, "POST", "/login", `{"user_id":"admin","password":"adminpass"}`)
	assert.Equal(t, 200, w.Code, "Failed to login admin: %s", w.Body.String())
	json.Unmarshal(w.Body.Bytes(), &response)
	adminToken := response["token"]

	log.Printf("User token: %+v", userToken)

	// 5. 创建容器
	w = performAuthRequest(router, "POST", "/container", "", userToken)
	assert.Equal(t, 201, w.Code)

	// 6. 启动容器
	w = performAuthRequest(router, "POST", "/container/start", "", userToken)
	assert.Equal(t, 200, w.Code)

	// 7. 停止容器
	w = performAuthRequest(router, "POST", "/container/stop", "", userToken)
	assert.Equal(t, 200, w.Code)

	// 8. 获取用户分数
	w = performAuthRequest(router, "GET", "/user/testuser/score", "", userToken)
	assert.Equal(t, 200, w.Code)

	// 9. 更新用户分数
	//w = performAuthRequest(router, "PUT", "/user/testuser/score", `{"score":95.5}`, userToken)
	//assert.Equal(t, 200, w.Code)

	// 10. 修改密码
	w = performAuthRequest(router, "POST", "/user/testuser/change-password", `{"old_password":"testpass","new_password":"newpass"}`, userToken)
	assert.Equal(t, 200, w.Code)

	// 11. 批量创建用户 (管理员操作)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "users.csv")
	part.Write([]byte("user1,pass1,class1,grade1\nuser2,pass2,class2,grade2"))
	writer.Close()

	w = performAuthRequestWithMultipart(router, "POST", "/admin/users/bulk-create", body, writer.FormDataContentType(), adminToken)
	assert.Equal(t, 200, w.Code)

	// 12. 获取所有学生 (管理员操作)
	w = performAuthRequest(router, "GET", "/admin/students", "", adminToken)
	assert.Equal(t, 200, w.Code)

	// 13. 删除用户 (管理员操作)
	w = performAuthRequest(router, "DELETE", "/admin/user/user1", "", adminToken)
	assert.Equal(t, 200, w.Code)

	// 14. 移除容器
	w = performAuthRequest(router, "DELETE", "/container", "", userToken)
	assert.Equal(t, 200, w.Code)

	// 15. 删除测试用户
	w = performAuthRequest(router, "DELETE", "/admin/user/testuser", "", adminToken)
	assert.Equal(t, 200, w.Code)
}

func performRequest(r http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func performAuthRequest(r http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func performAuthRequestWithMultipart(r http.Handler, method, path string, body *bytes.Buffer, contentType, token string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func cleanupTestData() {
	// 在这里清理测试数据,例如删除测试用户和容器
}
