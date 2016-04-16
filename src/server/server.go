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

var requireAuth bool

func Log(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func Run(port int, disableAuth bool) {
	//start := time.Now()
	r := mux.NewRouter()
	requireAuth = !disableAuth
	recaptcha.ReadSecret("./creds/recaptcha.json", "www.marktai.com")

	// user requests
	r.HandleFunc("/login", Log(login)).Methods("POST")
	r.HandleFunc("/verifySecret", Log(verifySecret)).Methods("POST")
	r.HandleFunc("/users", Log(makeUser)).Methods("POST")

	r.HandleFunc("/changePassword", Log(changePassword)).Methods("POST")

	r.HandleFunc("/authHeaders", Log(authHeaders)).Methods("POST")

	for {
		log.Printf("Running at 0.0.0.0:%d\n", port)
		log.Println(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), r))
		time.Sleep(1 * time.Second)
	}
}
