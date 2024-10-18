package api

import (
	"fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/models"
	"github.com/cynic-1/blockchain-edu-backend/internal/services"
	"github.com/gin-gonic/gin"
	"log"
	"mime/multipart"
	"net/http"
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

	if err := h.userService.CreateUser(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
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

	c.JSON(http.StatusOK, gin.H{"token": token})
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

func (h *Handler) GetStudentInfo(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	student, err := h.userService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"Student Info": student})
}

func (h *Handler) GetUserScore(c *gin.Context) {
	userID, err := getUserIDFromContext(c)
	_, err = h.userService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 这里应该调用容器服务获取最新成绩,然后更新数据库
	// 简化处理,直接返回数据库中的成绩
	c.JSON(http.StatusOK, gin.H{"score": 100})
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

	students, err := h.userService.GetAllStudents(class, grade)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"students": students})
}
