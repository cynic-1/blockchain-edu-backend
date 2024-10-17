package services

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/config"
	"github.com/cynic-1/blockchain-edu-backend/internal/database"
	"github.com/cynic-1/blockchain-edu-backend/internal/docker"
	"github.com/cynic-1/blockchain-edu-backend/internal/models"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"io"
	"log"
	"mime/multipart"
	"time"
)

type UserService struct {
	dockerManager *docker.DockerManager
}

func NewUserService() (*UserService, error) {
	dm, err := docker.NewDockerManager()
	if err != nil {
		return nil, err
	}
	return &UserService{dockerManager: dm}, nil
}

func (s *UserService) CreateUser(user *models.User) error {
	log.Printf("Attempting to create user: %+v", user)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return err
	}
	user.Password = string(hashedPassword)
	log.Printf("Hashed password: %s", user.Password)

	return database.DB.Create(user).Error
}

func (s *UserService) Login(userID, password string) (string, error) {
	var user models.User
	if err := database.DB.Where("user_id = ?", userID).First(&user).Error; err != nil {
		log.Printf("Error finding user %s: %v", userID, err)
		return "", errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", errors.New("invalid password")
	}

	// 创建 JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":  user.UserID,
		"isAdmin": user.IsAdmin,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // Token 有效期为24小时
	})

	// 签名并获得完整的编码后的字符串token
	tokenString, err := token.SignedString([]byte(config.AppConfig.JWT.Secret))
	if err != nil {
		log.Printf("Error generating token for user %s: %v", userID, err)
		return "", err
	}

	log.Printf("User logged in successfully: %s", userID)
	return tokenString, nil
}

func (s *UserService) ChangePassword(userID string, oldPassword, newPassword string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	// 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return fmt.Errorf("incorrect old password")
	}

	// 生成新密码的哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 更新密码
	return database.DB.Model(user).Update("password", string(hashedPassword)).Error
}

func (s *UserService) CreateContainer(userID string) (string, int, error) {
	log.Printf("Attempting to create container for user: %s", userID)

	user, err := s.GetUser(userID)
	if err != nil {
		return "", 0, err
	}

	if user.ContainerID != "" {
		return "", 0, errors.New("user already has a container")
	}

	port, err := s.allocatePort()
	if err != nil {
		return "", 0, err
	}

	containerID, err := s.dockerManager.CreateContainer(userID, port)
	if err != nil {
		return "", 0, err
	}

	user.ContainerID = containerID
	user.DockerPort = port
	if err := database.DB.Save(user).Error; err != nil {
		// 如果保存失败,需要删除已创建的容器
		err := s.dockerManager.RemoveContainer(context.Background(), containerID)
		if err != nil {
			return "", 0, err
		}
		return "", 0, err
	}

	return containerID, port, nil
}

func (s *UserService) StartContainer(userID string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	if user.ContainerID == "" {
		return errors.New("user does not have a container")
	}

	return s.dockerManager.StartContainer(context.Background(), user.ContainerID)
}

func (s *UserService) StopContainer(userID string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	if user.ContainerID == "" {
		return errors.New("user does not have a container")
	}

	return s.dockerManager.StopContainer(context.Background(), user.ContainerID)
}

func (s *UserService) RemoveContainer(userID string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	if user.ContainerID == "" {
		return errors.New("user does not have a container")
	}

	if err := s.dockerManager.RemoveContainer(context.Background(), user.ContainerID); err != nil {
		return err
	}

	user.ContainerID = ""
	user.DockerPort = 0
	return database.DB.Save(user).Error
}

// Admin
func (s *UserService) allocatePort() (int, error) {
	var maxPort int
	const minPort = 9001 // 设置最小端口为9001，确保大于9000

	// 查找当前最大端口号
	err := database.DB.Model(&models.User{}).Select("COALESCE(MAX(docker_port), ?)", minPort-1).Scan(&maxPort).Error
	if err != nil {
		return 0, err
	}

	// 如果最大端口小于最小端口，从最小端口开始分配
	if maxPort < minPort {
		maxPort = minPort - 1
	}

	// 查找下一个可用端口
	for {
		nextPort := maxPort + 1
		var count int64
		err := database.DB.Model(&models.User{}).Where("docker_port = ?", nextPort).Count(&count).Error
		if err != nil {
			return 0, err
		}

		if count == 0 {
			// 端口未被使用，可以分配
			return nextPort, nil
		}

		maxPort = nextPort
	}
}

func (s *UserService) GetUser(userID string) (*models.User, error) {
	var user models.User
	if err := database.DB.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserService) UpdateUserScore(userID string, score float64) error {
	return database.DB.Model(&models.User{}).Where("user_id = ?", userID).Update("score", score).Error
}

func (s *UserService) AdminChangePassword(userID string, newPassword string) error {
	// 获取用户
	var user models.User
	if err := database.DB.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return err
	}

	// 哈希新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 更新密码
	user.Password = string(hashedPassword)
	if err := database.DB.Save(&user).Error; err != nil {
		return err
	}

	return nil
}

func (s *UserService) DeleteUser(userID string) error {
	// 首先获取用户信息
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	// 检查用户是否有关联的容器
	if user.ContainerID != "" {
		// 如果有容器，尝试删除它
		if err := s.RemoveContainer(userID); err != nil {
			// 如果删除容器失败，记录错误但继续删除用户
			log.Printf("Failed to remove container for user %s: %v", userID, err)
		}
	}

	// 删除用户记录
	if err := database.DB.Delete(&user).Error; err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	return nil
}

func (s *UserService) BulkCreateUsers(file multipart.File) error {
	reader := csv.NewReader(file)

	// 开始数据库事务
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			tx.Rollback()
			return err
		}

		// 假设CSV格式为: UserID,Password,Class,Grade
		user := &models.User{
			UserID:   record[0],
			Password: record[1],
			Class:    record[2],
			Grade:    record[3],
		}

		if err := s.createUserWithinTransaction(tx, user); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func (s *UserService) createUserWithinTransaction(tx *gorm.DB, user *models.User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	return tx.Create(user).Error
}

func (s *UserService) GetAllStudents(class, grade string) ([]models.User, error) {
	var users []models.User
	query := database.DB.Where("is_admin = ?", false)

	if class != "" {
		query = query.Where("class = ?", class)
	}
	if grade != "" {
		query = query.Where("grade = ?", grade)
	}

	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}

	return users, nil
}
