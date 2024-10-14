package services

import (
	"github.com/yourusername/blockchain-edu-backend/internal/database"
	"github.com/yourusername/blockchain-edu-backend/internal/docker"
	"github.com/yourusername/blockchain-edu-backend/internal/models"
	"golang.org/x/crypto/bcrypt"
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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	// 分配 Docker 端口
	port, err := s.allocatePort()
	if err != nil {
		return err
	}
	user.DockerPort = port

	// 创建 Docker 容器
	containerID, err := s.dockerManager.CreateContainer(user.UserID, port)
	if err != nil {
		return err
	}
	user.ContainerID = containerID

	return database.DB.Create(user).Error
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

func (s *UserService) DeleteUser(userID string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	if err := s.dockerManager.RemoveContainer(user.ContainerID); err != nil {
		return err
	}

	return database.DB.Delete(&models.User{}, "user_id = ?", userID).Error
}

func (s *UserService) allocatePort() (int, error) {
	// 实现端口分配逻辑,确保不会重复
	// 这里简化处理,实际应用中需要更复杂的逻辑
	var maxPort int
	if err := database.DB.Model(&models.User{}).Select("COALESCE(MAX(docker_port), 8000)").Scan(&maxPort).Error; err != nil {
		return 0, err
	}
	return maxPort + 1, nil
}
