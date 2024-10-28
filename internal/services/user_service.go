package services

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/config"
	"github.com/cynic-1/blockchain-edu-backend/internal/database"
	"github.com/cynic-1/blockchain-edu-backend/internal/docker"
	"github.com/cynic-1/blockchain-edu-backend/internal/models"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"io"
	"log"
	"mime/multipart"
	"net/http"
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
		return "", err
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

type ScoreResponse struct {
	Native struct {
		DeployPcoin int `json:"/deploy/pcoin"`
		InvokePcoin int `json:"/invoke/pcoin"`
		InvokeXcoin int `json:"/invoke/xcoin"`
		QueryPcoin  int `json:"/query/pcoin"`
		QueryTaddr  int `json:"/query/taddr"`
		QueryXcoin  int `json:"/query/xcoin"`
	} `json:"native"`
	Setup struct {
		BuildChain      int `json:"/build/chain"`
		ClusterStart    int `json:"/cluster/start"`
		GenesisAddrs    int `json:"/genesis/addrs"`
		GenesisRandom   int `json:"/genesis/random"`
		GenesisTemplate int `json:"/genesis/template"`
		NewCluster      int `json:"/new/cluster"`
		NewFactory      int `json:"/new/factory"`
		ResetWorkdir    int `json:"/reset/workdir"`
	} `json:"setup"`
	Transaction struct {
		DeployContract int `json:"/deploy/contract"`
		InvokeContract int `json:"/invoke/contract"`
		NewClientNode  int `json:"/new/client/:node"`
		QueryContract  int `json:"/query/contract"`
		UploadContract int `json:"/upload/contract"`
	} `json:"transaction"`
}

// mergeScores 合并两个布尔数组，使用OR操作
func mergeScores(oldScore, newScore pq.BoolArray) pq.BoolArray {
	// 确定最终数组的长度
	maxLen := len(oldScore)
	if len(newScore) > maxLen {
		maxLen = len(newScore)
	}

	// 创建结果数组
	result := make(pq.BoolArray, maxLen)

	// 复制并合并数据
	for i := 0; i < maxLen; i++ {
		var oldVal, newVal bool
		if i < len(oldScore) {
			oldVal = oldScore[i]
		}
		if i < len(newScore) {
			newVal = newScore[i]
		}
		result[i] = oldVal || newVal
	}

	return result
}

func (s *UserService) GetUserScore(userID string) (pq.BoolArray, error) {
	var user models.User
	if err := database.DB.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return nil, fmt.Errorf("user not found: %v", err)
	}

	url := fmt.Sprintf("http://localhost:%d/scores", user.DockerPort)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get score from user container: %v", err)
	}
	defer resp.Body.Close()

	var scoreResp ScoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&scoreResp); err != nil {
		return nil, fmt.Errorf("failed to decode score: %v", err)
	}

	newScore := s.convertScoreResponseToBoolArray(scoreResp)

	// 使用辅助函数合并成绩
	mergedScore := mergeScores(user.Score, newScore)

	// 更新用户成绩
	user.Score = mergedScore
	if err := database.DB.Save(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to update score in database: %v", err)
	}

	return user.Score, nil
}

func (s *UserService) convertScoreResponseToBoolArray(resp ScoreResponse) pq.BoolArray {
	score := make(pq.BoolArray, models.ScoreCount)

	// Native
	score[models.ScoreDeployPcoin] = resp.Native.DeployPcoin > 1
	score[models.ScoreInvokePcoin] = resp.Native.InvokePcoin > 1
	score[models.ScoreInvokeXcoin] = resp.Native.InvokeXcoin > 1
	score[models.ScoreQueryPcoin] = resp.Native.QueryPcoin > 1
	score[models.ScoreQueryTaddr] = resp.Native.QueryTaddr > 1
	score[models.ScoreQueryXcoin] = resp.Native.QueryXcoin > 1

	// Setup
	score[models.ScoreBuildChain] = resp.Setup.BuildChain > 1
	score[models.ScoreClusterStart] = resp.Setup.ClusterStart > 1
	score[models.ScoreGenesisAddrs] = resp.Setup.GenesisAddrs > 1
	score[models.ScoreGenesisRandom] = resp.Setup.GenesisRandom > 1
	score[models.ScoreGenesisTemplate] = resp.Setup.GenesisTemplate > 1
	score[models.ScoreNewCluster] = resp.Setup.NewCluster > 1
	score[models.ScoreNewFactory] = resp.Setup.NewFactory > 1
	score[models.ScoreResetWorkdir] = resp.Setup.ResetWorkdir > 1

	// Transaction
	score[models.ScoreDeployContract] = resp.Transaction.DeployContract > 1
	score[models.ScoreInvokeContract] = resp.Transaction.InvokeContract > 1
	score[models.ScoreNewClientNode] = resp.Transaction.NewClientNode > 1
	score[models.ScoreQueryContract] = resp.Transaction.QueryContract > 1
	score[models.ScoreUploadContract] = resp.Transaction.UploadContract > 1

	return score
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

func (s *UserService) GetInactiveContainers(duration time.Duration) ([]string, error) {
	var inactiveUsers []string
	cutoffTime := time.Now().Add(-duration)

	err := database.DB.Model(&models.User{}).
		Where("last_activity < ? AND container_id IS NOT NULL", cutoffTime).
		Pluck("user_id", &inactiveUsers).Error

	return inactiveUsers, err
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

func (s *UserService) UpdateUserInfo(userID, name, class, grade string) error {
	// 首先检查用户是否存在
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	// 更新用户信息
	updates := map[string]interface{}{}
	if name != "" {
		updates["name"] = name
	}
	if class != "" {
		updates["class"] = class
	}
	if grade != "" {
		updates["grade"] = grade
	}

	// 如果没有需要更新的字段，直接返回
	if len(updates) == 0 {
		return nil
	}

	// 执行更新
	if err := database.DB.Model(user).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update user information: %v", err)
	}

	return nil
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

		// 假设CSV格式为: UserID,Name,Password,Class,Grade
		if len(record) < 5 {
			tx.Rollback()
			return fmt.Errorf("invalid CSV format: expected at least 5 columns")
		}

		// 假设CSV格式为: UserID,Password,Class,Grade
		user := &models.User{
			UserID:   record[0],
			Name:     record[1],
			Password: record[2],
			Class:    record[3],
			Grade:    record[4],
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

func (s *UserService) GetStudentsPaginated(class, grade string, page, pageSize int) ([]models.User, int64, error) {
	var users []models.User
	var totalCount int64

	query := database.DB.Model(&models.User{}).Where("is_admin = ?", false)

	if class != "" {
		query = query.Where("class = ?", class)
	}
	if grade != "" {
		query = query.Where("grade = ?", grade)
	}

	// 获取总数
	if err := query.Count(&totalCount).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Find(&users).Error
	if err != nil {
		return nil, 0, err
	}

	return users, totalCount, nil
}

func (s *UserService) CleanupInactiveContainers(inactivityThreshold time.Duration) error {
	return s.dockerManager.CleanupInactiveContainers(inactivityThreshold)
}

func (s *UserService) ExportStudentsToCSV(class, grade string) ([]byte, error) {
	// 查询符合条件的学生
	var users []models.User
	query := database.DB.Where("is_admin = ?", false)

	if class != "" {
		query = query.Where("class = ?", class)
	}
	if grade != "" {
		query = query.Where("grade = ?", grade)
	}

	if err := query.Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to query users: %v", err)
	}

	// 创建一个buffer来写入CSV数据
	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)

	// 写入CSV头部
	headers := []string{
		"UserID", "Name", "Class", "Grade",
		// Setup scores
		"NewFactory", "ResetWorkdir", "GenesisAddrs", "GenesisRandom", "GenesisTemplate",
		"NewCluster", "BuildChain", "ClusterStart",
		// Transaction scores
		"NewClientNode", "UploadContract", "DeployContract", "InvokeContract", "QueryContract",
		// Native scores
		"DeployPcoin", "InvokePcoin", "QueryPcoin", "InvokeXcoin", "QueryXcoin", "QueryTaddr",
	}

	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("failed to write headers: %v", err)
	}

	// 写入每个用户的数据
	for _, user := range users {
		// 将bool数组转换为字符串数组
		scoreStrs := make([]string, models.ScoreCount)
		for i := 0; i < models.ScoreCount; i++ {
			if i < len(user.Score) && user.Score[i] {
				scoreStrs[i] = "1"
			} else {
				scoreStrs[i] = "0"
			}
		}

		// 组合所有字段
		record := []string{
			user.UserID,
			user.Name,
			user.Class,
			user.Grade,
		}
		record = append(record, scoreStrs...)

		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write record: %v", err)
		}
	}

	// 确保所有数据都写入buffer
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("failed to flush writer: %v", err)
	}

	return buf.Bytes(), nil
}
