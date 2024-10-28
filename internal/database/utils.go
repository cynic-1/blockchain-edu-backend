package database

import (
	"errors"
	"github.com/lib/pq"
)

// IsUniqueViolationError 检查错误是否为唯一约束违反
func IsUniqueViolationError(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505" // PostgreSQL 唯一约束违反的错误代码
	}
	return false
}
