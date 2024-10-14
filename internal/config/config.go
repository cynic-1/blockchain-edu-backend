package config

type Config struct {
	DatabaseURL string
	JWTSecret   string
	DockerImage string
	// 添加其他配置项
}

var AppConfig Config

func LoadConfig() {
	// 从环境变量或配置文件中加载配置
	// 这里简化处理,实际应用中应该使用 viper 等库
	AppConfig = Config{
		DatabaseURL: "postgres://user:password@localhost:5432/blockchain_edu",
		JWTSecret:   "your-secret-key",
		DockerImage: "your-blockchain-image:latest",
	}
}
