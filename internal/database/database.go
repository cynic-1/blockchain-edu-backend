package database

import (
	"fmt"
	"github.com/cynic-1/blockchain-edu-backend/internal/config"
	"github.com/cynic-1/blockchain-edu-backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	dbConfig := config.AppConfig.Database
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		dbConfig.Host, dbConfig.Port, dbConfig.User, dbConfig.Password, dbConfig.DBName)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
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
