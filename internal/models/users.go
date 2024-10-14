package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	UserID      string `gorm:"uniqueIndex"`
	Password    string
	Class       string
	Grade       string
	Score       float64
	DockerPort  int
	ContainerID string
	IsAdmin     bool
}
