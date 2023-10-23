package db

import (
	"database/sql"
	_ "github.com/lib/pq"

	"log"
)

var (
	Db        *sql.DB
	closeChan chan bool
)

func Open() {
	closeChan = make(chan bool)
	var err error
	Db, err = sql.Open("postgres",
		"host=db port=5432 user=postgres password=postgres dbname=auth sslmode=disable")

	if err != nil {
		log.Fatal(err)
	}
	go func() {
		<-closeChan
		Db.Close()
	}()
}

func Close() {
	closeChan <- true
}
