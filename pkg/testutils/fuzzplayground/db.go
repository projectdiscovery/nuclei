package fuzzplayground

import (
	"database/sql"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db        *sql.DB
	tempDBDir string
)

func init() {
	dir, err := os.MkdirTemp("", "fuzzplayground-*")
	if err != nil {
		panic(err)
	}
	tempDBDir = dir

	db, err = sql.Open("sqlite3", fmt.Sprintf("file:%v/test.db?cache=shared&mode=memory", tempDBDir))
	if err != nil {
		panic(err)
	}
	addDummyUsers(db)
	addDummyPosts(db)
}

// Cleanup cleans up the temporary database directory
func Cleanup() {
	if db != nil {
		_ = db.Close()
	}
	if tempDBDir != "" {
		_ = os.RemoveAll(tempDBDir)
	}
}

type User struct {
	XMLName xml.Name `xml:"user"`
	ID      int      `xml:"id"`
	Name    string   `xml:"name"`
	Age     int      `xml:"age"`
	Role    string   `xml:"role"`
}

func addDummyUsers(db *sql.DB) {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, role TEXT)")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO users (id , name, age, role) VALUES (1,'admin', 30, 'admin')")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO users (id , name, age, role) VALUES (75,'user', 30, 'user')")
	if err != nil {
		panic(err)
	}
}

func patchUnsanitizedUser(db *sql.DB, user User) error {
	setClauses := ""

	if user.Name != "" {
		setClauses += "name = '" + user.Name + "', "
	}
	if user.Age > 0 {
		setClauses += "age = " + strconv.Itoa(user.Age) + ", "
	}
	if user.Role != "" {
		setClauses += "role = '" + user.Role + "', "
	}
	if setClauses == "" {
		// No fields to update
		return nil
	}
	setClauses = strings.TrimSuffix(setClauses, ", ")

	query := "UPDATE users SET " + setClauses + " WHERE id = ?"
	_, err := db.Exec(query, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func getUnsanitizedUser(db *sql.DB, id string) (User, error) {
	var user User
	err := db.QueryRow("SELECT id, name, age, role FROM users WHERE id = "+id).Scan(&user.ID, &user.Name, &user.Age, &user.Role)
	if err != nil {
		return user, err
	}
	return user, nil
}

type Posts struct {
	ID      int
	Title   string
	Content string
	Lang    string
}

func addDummyPosts(db *sql.DB) {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, title TEXT, content TEXT, lang TEXT)")
	if err != nil {
		panic(err)
	}
	// Inserting English dummy posts
	_, err = db.Exec("INSERT INTO posts (id, title, content, lang) VALUES (1, 'The Joy of Programming', 'Programming is like painting a canvas with logic.', 'en')")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO posts (id, title, content, lang) VALUES (2, 'A Journey Through Code', 'Every line of code tells a story.', 'en')")
	if err != nil {
		panic(err)
	}
	// Inserting a Spanish dummy post
	_, err = db.Exec("INSERT INTO posts (id, title, content, lang) VALUES (3, 'La belleza del código', 'Cada función es un poema en un mar de algoritmos.', 'es')")
	if err != nil {
		panic(err)
	}
}

func getUnsanitizedPostsByLang(db *sql.DB, lang string) ([]Posts, error) {
	var posts []Posts
	query := "SELECT id, title, content, lang FROM posts WHERE lang = '" + lang + "'"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var post Posts
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Lang); err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return posts, nil
}
