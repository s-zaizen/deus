package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func userHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := fmt.Sprintf("SELECT id, name, role FROM users WHERE name = '%s'", name)
	rows, _ := db.Query(query)
	defer rows.Close()
	io.WriteString(w, "ok")
}

func backupHandler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	cmd := exec.Command("sh", "-c", "tar czf /tmp/backup.tgz "+path)
	output, _ := cmd.CombinedOutput()
	w.Write(output)
}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	sum := md5.Sum([]byte(password))
	io.WriteString(w, fmt.Sprintf("%x", sum))
}

func main() {
	db, _ = sql.Open("sqlite3", "/tmp/makina-demo.db")
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/backup", backupHandler)
	http.HandleFunc("/fetch", fetchHandler)
	http.HandleFunc("/token", tokenHandler)
	http.ListenAndServe(":3003", nil)
}
