package models

import (
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UserID      string       `gorm:"uniqueIndex" json:"user_id"`
	Password    string       `json:"password"`
	Class       string       `json:"class"`
	Grade       string       `json:"grade"`
	Score       pq.BoolArray `gorm:"type:boolean[];default:'{false,false,false,false,false,false,false,false,false,false,false,false}'" json:"score"`
	DockerPort  int          `json:"docker_port"`
	ContainerID string       `json:"container_id"`
	IsAdmin     bool         `json:"is_admin"`
}

const (
	// Setup scores
	ScoreBuildChain = iota
	ScoreGenesisAddrs
	ScoreGenesisRandom
	ScoreGenesisTemplate
	ScoreNewClientde
	ScoreNewCluster
	ScoreNewFactory
	ScoreResetWorkdir

	// Transaction scores
	ScoreDeployContract
	ScoreInvokeContract
	ScoreQueryContract
	ScoreUploadContract

	ScoreCount // 总的 score 数量
)

func (u *User) SetScoreFromMap(scoreMap map[string]map[string]bool) {
	setupScores := scoreMap["/setup"]
	transactionScores := scoreMap["/transaction"]

	u.Score[ScoreBuildChain] = setupScores["/build/chain"]
	u.Score[ScoreGenesisAddrs] = setupScores["/genesis/addrs"]
	u.Score[ScoreGenesisRandom] = setupScores["/genesis/random"]
	u.Score[ScoreGenesisTemplate] = setupScores["/genesis/template"]
	u.Score[ScoreNewClientde] = setupScores["/new/clientde"]
	u.Score[ScoreNewCluster] = setupScores["/new/cluster"]
	u.Score[ScoreNewFactory] = setupScores["/new/factory"]
	u.Score[ScoreResetWorkdir] = setupScores["/reset/workdir"]

	u.Score[ScoreDeployContract] = transactionScores["/deploy/contract"]
	u.Score[ScoreInvokeContract] = transactionScores["/invoke/contract"]
	u.Score[ScoreQueryContract] = transactionScores["/query/contract"]
	u.Score[ScoreUploadContract] = transactionScores["/upload/contract"]
}
