package database

import (
	"github.com/yourusername/blockchain-edu-backend/internal/config"
	"github.com/yourusername/blockchain-edu-backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	var err error
	DB, err = gorm.Open(postgres.Open(config.AppConfig.DatabaseURL), &gorm.Config{})
	if err != nil {
		return err
	}

	// 自动迁移
	err = DB.AutoMigrate(&models.User{})
	if err != nil {
		return err
	}

	return nil
}
