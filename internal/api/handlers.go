package api

import (
	"github.com/gin-gonic/gin"
	"github.com/yourusername/blockchain-edu-backend/internal/models"
	"github.com/yourusername/blockchain-edu-backend/internal/services"
	"net/http"
)

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

func (h *Handler) GetUserScore(c *gin.Context) {
	userID := c.Param("userID")
	user, err := h.userService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 这里应该调用容器服务获取最新成绩,然后更新数据库
	// 简化处理,直接返回数据库中的成绩
	c.JSON(http.StatusOK, gin.H{"score": user.Score})
}

func (h *Handler) UpdateUserScore(c *gin.Context) {
	userID := c.Param("userID")
	var scoreData struct {
		Score float64 `json:"score"`
	}
	if err := c.ShouldBindJSON(&scoreData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.UpdateUserScore(userID, scoreData.Score); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Score updated successfully"})
}

func (h *Handler) DeleteUser(c *gin.Context) {
	userID := c.Param("userID")
	if err := h.userService.DeleteUser(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}
