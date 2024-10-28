package api

import (
	"fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/database"
	"github.com/cynic-1/blockchain-edu-backend/internal/models"
	"github.com/cynic-1/blockchain-edu-backend/internal/services"
	"github.com/gin-gonic/gin"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

// getUserIDFromContext 从 Gin 上下文中获取用户 ID
func getUserIDFromContext(c *gin.Context) (string, error) {
	userID, exists := c.Get("userID")
	if !exists {
		return "", fmt.Errorf("user not authenticated")
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return "", fmt.Errorf("invalid user ID")
	}

	return userIDStr, nil
}

type Handler struct {
	userService *services.UserService
}

func NewHandler() (*Handler, error) {
	userService, err := services.NewUserService()
	if err != nil {
		return nil, err
	}
	return &Handler{userService: userService}, nil
}

func (h *Handler) RegisterUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证必要字段
	if user.UserID == "" || user.Name == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID、姓名和密码不能为空"})
		return
	}

	// 普通注册接口只能注册学生账号
	user.IsAdmin = false

	if err := h.userService.CreateUser(&user); err != nil {
		// 检查是否是唯一约束违反错误
		if database.IsUniqueViolationError(err) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "用户ID已存在",
				"code":  "USER_ID_EXISTS",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 只有学生账号才创建容器
	_, _, err := h.userService.CreateContainer(user.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create container: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

func (h *Handler) RegisterAdmin(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证必要字段
	if user.UserID == "" || user.Name == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户ID、姓名和密码不能为空"})
		return
	}

	// 设置为管理员账号
	user.IsAdmin = true

	if err := h.userService.CreateUser(&user); err != nil {
		if database.IsUniqueViolationError(err) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "用户ID已存在",
				"code":  "USER_ID_EXISTS",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Admin created successfully"})
}

func (h *Handler) Login(c *gin.Context) {
	var loginData struct {
		UserID   string `json:"user_id" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := h.userService.Login(loginData.UserID, loginData.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetUser(loginData.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 只有学生账号才需要启动容器
	if !user.IsAdmin {
		if err := h.userService.StartContainer(user.UserID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start container: " + err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"token": token, "userInfo": user})
}

func (h *Handler) CreateContainer(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	log.Printf("CreateContainer called for user: %s", userID)

	containerID, port, err := h.userService.CreateContainer(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Printf(err.Error())

		return
	}
	c.JSON(http.StatusCreated, gin.H{"container_id": containerID, "port": port})
}

func (h *Handler) StartContainer(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	log.Printf("StartContainer called for user: %s", userID)

	if err := h.userService.StartContainer(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Container started successfully"})
}

func (h *Handler) StopContainer(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Stop called for user: %s", userID)

	if err := h.userService.StopContainer(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Container stopped successfully"})
}

func (h *Handler) RemoveContainer(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	log.Printf("RemoveContainer called for user: %s", userID)

	if err := h.userService.RemoveContainer(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Container removed successfully"})
}

func (h *Handler) GetUserInfo(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	user, err := h.userService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"userInfo": user})
}

func (h *Handler) GetUserScore(c *gin.Context) {
	userID, err := getUserIDFromContext(c)

	score, err := h.userService.GetUserScore(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"score": score})
}

func (h *Handler) ChangePassword(c *gin.Context) {
	userID, _ := getUserIDFromContext(c)

	var passwordData struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&passwordData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.ChangePassword(userID, passwordData.OldPassword, passwordData.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

//func (h *Handler) UpdateUserScore(c *gin.Context) {
//	userID := c.Param("userID")
//	var scoreData struct {
//		Score float64 `json:"score"`
//	}
//	if err := c.ShouldBindJSON(&scoreData); err != nil {
//		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
//		return
//	}
//
//	if err := h.userService.UpdateUserScore(userID, scoreData.Score); err != nil {
//		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
//		return
//	}
//
//	c.JSON(http.StatusOK, gin.H{"message": "Score updated successfully"})
//}

// Admin
func (h *Handler) DeleteUser(c *gin.Context) {
	userID := c.Param("userID")
	if err := h.userService.DeleteUser(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func (h *Handler) AdminChangePassword(c *gin.Context) {
	userID := c.Param("userID")

	var passwordData struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&passwordData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.AdminChangePassword(userID, passwordData.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// 在 handlers.go 中添加
func (h *Handler) UpdateUserInfo(c *gin.Context) {
	userID := c.Param("userID")

	// 定义请求体结构
	var updateData struct {
		Name  string `json:"name"`
		Class string `json:"class"`
		Grade string `json:"grade"`
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 调用 service 层方法更新用户信息
	if err := h.userService.UpdateUserInfo(userID, updateData.Name, updateData.Class, updateData.Grade); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User information updated successfully"})
}

func (h *Handler) BulkCreateUsers(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is required"})
		return
	}
	defer func(file multipart.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	if err := h.userService.BulkCreateUsers(file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Users created successfully"})
}

func (h *Handler) GetAllStudents(c *gin.Context) {
	class := c.Query("class")
	grade := c.Query("grade")

	// 获取分页参数
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if err != nil || pageSize < 1 {
		pageSize = 10
	}

	// 设置最大页面大小，防止请求过大的数据量
	maxPageSize := 100
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	students, totalCount, err := h.userService.GetStudentsPaginated(class, grade, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 计算总页数，注意类型转换
	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))

	c.JSON(http.StatusOK, gin.H{
		"students":    students,
		"total_count": totalCount,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

func (h *Handler) CleanupInactiveContainers(inactivityThreshold time.Duration) error {
	return h.userService.CleanupInactiveContainers(inactivityThreshold)
}

func (h *Handler) ExportStudents(c *gin.Context) {
	// 获取查询参数
	class := c.Query("class")
	grade := c.Query("grade")

	// 导出数据
	csvData, err := h.userService.ExportStudentsToCSV(class, grade)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 生成文件名
	timestamp := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("students_export_%s.csv", timestamp)

	// 设置响应头
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Expires", "0")
	c.Header("Cache-Control", "must-revalidate")
	c.Header("Pragma", "public")
	c.Header("Content-Length", fmt.Sprint(len(csvData)))

	// 写入响应
	c.Writer.Write(csvData)
}
