package models

import (
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UserID      string       `gorm:"uniqueIndex" json:"user_id"`
	Password    string       `json:"password"`
	Name        string       `json:"name"`
	Class       string       `json:"class"`
	Grade       string       `json:"grade"`
	Score       pq.BoolArray `gorm:"type:boolean[];default:'{false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false}'" json:"score"`
	DockerPort  int          `json:"docker_port"`
	ContainerID string       `json:"container_id"`
	IsAdmin     bool         `json:"is_admin"`
}

// 在 models/constants.go 中
const (
	// Setup scores
	ScoreNewFactory = iota
	ScoreResetWorkdir
	ScoreGenesisAddrs
	ScoreGenesisRandom
	ScoreGenesisTemplate
	ScoreNewCluster
	ScoreBuildChain
	ScoreClusterStart

	// Transaction scores
	ScoreNewClientNode
	ScoreUploadContract
	ScoreDeployContract
	ScoreInvokeContract
	ScoreQueryContract

	// Native scores
	ScoreDeployPcoin
	ScoreInvokePcoin
	ScoreQueryPcoin
	ScoreInvokeXcoin
	ScoreQueryXcoin
	ScoreQueryTaddr

	// Total number of scores
	ScoreCount
)
