package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

var db *sql.DB

const usersTable = "users"

func lookup(name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = '" + name + "'") // VULN:sqli
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	lookup(name)
	file := r.FormValue("file")
	data, _ := os.ReadFile(filepath.Join("/srv/data", file)) // VULN:path_traversal
	w.Write(data)
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output() // VULN:cmdi
	w.Write(out)
	fmt.Fprintf(w, "<p>Hello %s</p>", r.FormValue("who")) // VULN:xss
	target := r.URL.Query().Get("url")
	http.Get(target) // VULN:ssrf
	sum := md5.Sum([]byte(name)) // VULN:weak_crypto
	fmt.Println(sum)

	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	db.Query(fmt.Sprintf("SELECT * FROM orders WHERE id = %d", id))
	db.Query("SELECT COUNT(*) FROM " + usersTable)
	doc := filepath.Base(r.FormValue("doc"))
	os.ReadFile(filepath.Join("/srv/docs", doc))
	exec.Command("ls", "-l", "/srv").Output()
}
