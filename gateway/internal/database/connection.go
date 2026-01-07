package database

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql" // Need this import
)

func ConnectSQL(user, pass, host, name string) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, name)
	return sql.Open("mysql", dsn)
}