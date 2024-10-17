package config

import (
	"github.com/spf13/viper"
	"log"
)

type Config struct {
	Database struct {
		Host     string
		Port     int
		User     string
		Password string
		DBName   string
	}
	JWT struct {
		Secret string
		Expiry int // 单位: 小时
	}
	Docker struct {
		Image string
	}
	Server struct {
		Port int
	}
}

var AppConfig Config

func LoadConfig(configPath string) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	if err := viper.Unmarshal(&AppConfig); err != nil {
		log.Fatalf("Unable to decode into struct: %s", err)
	}
}
