package server

import (
	"fmt"
	"github.com/gorilla/mux"
	_ "github.com/gorilla/websocket"
	"log"
	"net/http"
	"recaptcha"
	"time"
)

var requireEmail bool
var requireAuth bool

func Log(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func Run(port int, disableAuth bool, disableEmail bool) {
	//start := time.Now()
	r := mux.NewRouter()
	requireAuth = !disableAuth
	requireEmail = !disableEmail
	recaptcha.ReadSecret("./creds/recaptcha.json", "www.marktai.com")

	// user requests
	r.HandleFunc("/login", Log(login)).Methods("POST")
	r.HandleFunc("/logout", Log(logout)).Methods("POST")
	r.HandleFunc("/verifySecret", Log(verifySecret)).Methods("POST")
	r.HandleFunc("/users", Log(makeUser)).Methods("POST")
	r.HandleFunc("/register/{userID:[0-9]+}/{registrationCode:[0-9a-fA-F]+}", Log(registerUser)).Methods("GET")
	r.HandleFunc("/users/{userID:[0-9]+}/registered", Log(checkRegistered)).Methods("GET")

	r.HandleFunc("/changePassword", Log(changePassword)).Methods("POST")

	r.HandleFunc("/authHeaders", Log(authHeaders)).Methods("POST")
	r.HandleFunc("/email", Log(sendEmail)).Methods("POST")

	authMessage := ""
	emailMessage := ""
	for {
		if requireAuth {
			authMessage = "with authentication"
		} else {
			authMessage = "without authentication"
		}

		if requireEmail {
			emailMessage = "with emails"
		} else {
			emailMessage = "without emails"
		}
		log.Printf("Running at 0.0.0.0:%d, %s, %s\n", port, authMessage, emailMessage)
		log.Println(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), r))
		time.Sleep(10 * time.Second)
	}
}
