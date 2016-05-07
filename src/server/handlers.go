package server

import (
	"auth"
	"encoding/json"
	"fmt"
	// "github.com/gorilla/mux"
	// "io/ioutil"
	"encoding/base64"
	// "errors"
	"log"
	// "math/rand"
	"net/http"
	"recaptcha"
	"strings"
)

func login(w http.ResponseWriter, r *http.Request) {

	var parsedJson map[string]string
	if encodedAuth := r.Header.Get("Authorization"); encodedAuth != "" {
		authBytes, err := base64.StdEncoding.DecodeString(encodedAuth)
		if err != nil {
			//ERROR
		}
		auth := string(authBytes[:])
		if strings.Count(auth, ":") != 1 {
			// ERROR
		}
		authSlice := strings.Split(auth, ":")

		parsedJson = make(map[string]string)
		parsedJson["User"] = authSlice[0]
		parsedJson["Password"] = authSlice[1]
	} else {

		decoder := json.NewDecoder(r.Body)

		err := decoder.Decode(&parsedJson)
		if err != nil {
			WriteErrorString(w, err.Error()+" in parsing POST body (JSON)", 400)
			return
		}
	}

	user, ok := parsedJson["User"]
	if !ok {
		WriteErrorString(w, "No 'User' set in POST body", 400)
		return
	}
	pass, ok := parsedJson["Password"]
	if !ok {
		WriteErrorString(w, "No 'Password' set in POST body", 400)
		return
	}

	userID, secret, err := auth.Login(user, pass)
	if err != nil {
		// hides details about server from login attempts"
		log.Println(err)
		WriteErrorString(w, "User and password combination incorrect", 401)
		return
	}

	retMap := map[string]string{"UserID": fmt.Sprintf("%d", userID), "Secret": secret.Base64(), "Expiration": secret.ExpirationUTC()}
	WriteJson(w, retMap)
}

func verifySecret(w http.ResponseWriter, r *http.Request) {

	decoder := json.NewDecoder(r.Body)
	var parsedJson map[string]string
	err := decoder.Decode(&parsedJson)
	if err != nil {
		WriteErrorString(w, err.Error()+" in parsing POST body (JSON)", 400)
		return
	}

	user, ok := parsedJson["User"]
	if !ok {
		WriteErrorString(w, "No 'User' set in POST body", 400)
		return
	}
	inpSecret, ok := parsedJson["Secret"]
	if !ok {
		WriteErrorString(w, "No 'Secret' set in POST body", 400)
		return
	}

	userID, secret, err := auth.VerifySecret(user, inpSecret)
	if err != nil {
		// hides details about server from login attempts"
		log.Println(err)
		WriteErrorString(w, "User and secret combination incorrect", 401)
		return
	}

	retMap := map[string]string{"UserID": fmt.Sprintf("%d", userID), "Secret": secret.Base64(), "Expiration": secret.ExpirationUTC()}
	WriteJson(w, retMap)
}

func makeUser(w http.ResponseWriter, r *http.Request) {

	secret := r.FormValue("Secret")
	if secret != "thisisatotallysecuresecret" {
		WriteErrorString(w, "Sorry, you can't make a user now", 500)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var parsedJson map[string]string
	err := decoder.Decode(&parsedJson)
	if err != nil {
		WriteError(w, err, 400)
		return
	}

	user, ok := parsedJson["User"]
	if !ok {
		WriteErrorString(w, "No 'User' set in POST body", 400)
		return
	}
	pass, ok := parsedJson["Password"]
	if !ok {
		WriteErrorString(w, "No 'Password' set in POST body", 400)
		return
	}

	if requireAuth {
		recaptchaResponse, ok := parsedJson["Recaptcha"]
		if !ok {
			WriteErrorString(w, "No 'Recaptcha' set in POST body", 400)
			return
		}
		verified, timestamp, hostname, err := recaptcha.Verify(recaptchaResponse)
		if err != nil {
			WriteError(w, err, 500)
			return
		}
		if !verified {
			WriteErrorString(w, "Recaptcha not verified successfully", 400)
			return
		}
		_ = timestamp
		_ = hostname
	}

	userID, err := auth.MakeUser(user, pass)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	WriteJson(w, genMap("UserID", userID))
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var parsedJson map[string]string
	err := decoder.Decode(&parsedJson)
	if err != nil {
		WriteError(w, err, 400)
		return
	}

	user, ok := parsedJson["User"]
	if !ok {
		WriteErrorString(w, "No 'User' set in POST body", 400)
		return
	}

	pass, ok := parsedJson["Password"]
	if !ok {
		WriteErrorString(w, "No 'Password' set in POST body", 400)
		return
	}

	var userID uint

	newPass, ok := parsedJson["NewPassword"]
	if !ok {
		WriteErrorString(w, "No 'NewPassword' set in POST body", 400)
		return
	}

	if requireAuth {
		userID, _, err = auth.Login(user, pass)
		if err != nil {
			log.Println(err)
			WriteErrorString(w, "Not Authorized Request", 401)
			return
		}
	} else {
		userID, err = auth.GetUserID(user)
		if err != nil {
			log.Println(err)
			WriteErrorString(w, "No user with that username", 401)
			return
		}
	}

	err = auth.ChangePassword(userID, newPass)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	w.WriteHeader(200)
}

func authHeaders(w http.ResponseWriter, r *http.Request) {
	authed, err := auth.AuthRequestHeaders(r)
	if err != nil || !authed {
		if err != nil {
			log.Println(err)
		}
		WriteErrorString(w, "Not Authorized Request", 401)
		return
	}

	w.WriteHeader(200)
}
