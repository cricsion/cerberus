package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("ping", host).Output()
	user := r.URL.Query().Get("user")
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user))
	defer rows.Close()
	w.Write(out)
}

func main() {
	http.HandleFunc("/run", handler)
}
