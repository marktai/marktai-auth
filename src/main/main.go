package main

import (
	"db"
	"flag"
	"server"
)

func main() {
	// // makeUser()
	// testHMAC()

	// _, secret, err := auth.Login("me", "password")
	// if err != nil {
	// 	log.Panic(err)
	// }
	// log.Printf("%s", secret.String())
	var port int
	var disableAuth bool

	flag.IntVar(&port, "port", 8043, "Port the server listens to")
	flag.BoolVar(&disableAuth, "disableAuth", false, "Disables authentication requirements")

	flag.Parse()

	db.Open()
	defer db.Db.Close()
	server.Run(port, disableAuth)
}
