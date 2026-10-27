package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func userHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	db.Query("SELECT * FROM users WHERE id = $1", id)
}

func run(name string) {
	exec.Command("sh", "-c", "tar czf "+name)
	exec.Command("ls", "-l")
}

func digest(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}
