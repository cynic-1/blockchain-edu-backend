package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	UserID      string  `gorm:"uniqueIndex" json:"user_id"`
	Password    string  `json:"password"`
	Class       string  `json:"class"`
	Grade       string  `json:"grade"`
	Score       float64 `json:"score"`
	DockerPort  int     `json:"docker_port"`
	ContainerID string  `json:"container_id"`
	IsAdmin     bool    `json:"is_admin"`
}
