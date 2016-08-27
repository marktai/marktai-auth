package server

import (
	"auth"
	"email"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	// "errors"
	valid "github.com/asaskevich/govalidator"
	"log"
	"net/http"
	"recaptcha"
	"strconv"
	"strings"
)

func login(w http.ResponseWriter, r *http.Request) {

	var parsedJson map[string]string
	if encodedAuth := r.Header.Get("Authorization"); encodedAuth != "" {
		// support for HTTP Authorization header
		// https://en.wikipedia.org/wiki/Basic_access_authentication
		authBytes, err := base64.StdEncoding.DecodeString(encodedAuth)
		if err != nil {
			WriteErrorString(w, "Error decoding base64 in 'Authorization' header", 400)
			return
		}
		auth := string(authBytes[:])
		if strings.Count(auth, ":") != 1 {
			WriteErrorString(w, "Not exactly 1 colon in 'Authorization' header", 400)
			return
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

	stayLoggedIn := false

	if parsedStr, ok := parsedJson["StayLoggedIn"]; ok {
		parsedBool, err := strconv.ParseBool(parsedStr)
		if err != nil {
			// stay default
		} else {
			stayLoggedIn = parsedBool
		}
	}

	userID, secret, err := auth.Login(user, pass, stayLoggedIn)
	if err != nil {
		// hides details about server from login attempts
		log.Println(err)
		WriteErrorString(w, "User and password combination incorrect", 401)
		return
	}

	retMap := map[string]string{"UserID": fmt.Sprintf("%d", userID), "Secret": secret.Base64(), "Expiration": secret.ExpirationUTC()}
	WriteJson(w, retMap)
}

func logout(w http.ResponseWriter, r *http.Request) {
	authed, err := auth.AuthRequestHeaders(r)

	if err != nil || !authed {
		if err != nil {
			log.Println(err)
		}
		WriteErrorString(w, "Not Authorized Request", 401)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var parsedJson map[string]string
	err = decoder.Decode(&parsedJson)
	if err != nil {
		WriteErrorString(w, err.Error()+" in parsing POST body (JSON)", 400)
		return
	}

	userIDString, ok := parsedJson["UserID"]
	if !ok {
		WriteErrorString(w, "No 'UserID' set in POST body", 400)
		return
	}

	userID, err := stringtoUint(userIDString)
	if err != nil {
		WriteError(w, err, 400)
	}

	err = auth.Logout(userID)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	w.WriteHeader(200)

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

	var emailString string
	if requireEmail {
		emailString, ok = parsedJson["Email"]
		if !ok {
			WriteErrorString(w, "No 'Email' set in POST body", 400)
			return
		}
		if !valid.IsEmail(emailString) {
			WriteErrorString(w, "Invalid email", 400)
			return
		}
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

	userID, err := auth.MakeUser(user, pass, emailString)
	pass = "" // Paranoid cleaning of password from stack
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	if requireEmail {
		codeString, err := auth.GetRegistrationCode(userID)
		if err != nil {
			log.Println("In emailing %s: %s", emailString, err.Error())
			WriteErrorString(w, "Error sending email", 500)
			return
		}
		subject := "Email Registration for marktai.com"

		link := fmt.Sprintf("https://www.marktai.com/T9/auth/users/%d/register?code=%s", userID, codeString)

		body := fmt.Sprintf("Dear %s, \nPlease use the following link to register your account:\n\t%s\n\nFrom,\nMark Tai", user, link)

		newEmail := email.Email{
			Recipient: emailString,
			Subject:   subject,
			Body:      body,
		}

		err = email.SendMail("www.marktai.com:25", newEmail)
		if err != nil {
			log.Println("In emailing %s: %s", emailString, err.Error())
			WriteErrorString(w, "Error sending email", 500)
			return
		}
	}

	WriteJson(w, genMap("UserID", userID))
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := stringtoUint(vars["userID"])
	if err != nil {
		WriteErrorString(w, "Error parsing userID", 400)
		return
	}

	registrationCode := r.FormValue("code")
	if registrationCode == "" {
		WriteErrorString(w, "No 'code' query given", 400)
		return
	}

	err = auth.UseRegistrationCode(userID, registrationCode)
	if err != nil {
		WriteError(w, err, 500)
		return
	}

	http.Redirect(w, r, "https://www.marktai.com/meta-tic-tac-toe/", 302)
}

func checkRegistered(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := stringtoUint(vars["userID"])
	if err != nil {
		WriteErrorString(w, "Error parsing userID", 400)
		return
	}
	authed, err := auth.AuthRequestHeaders(r)
	if err != nil || !authed {
		ignore := false
		if err != nil {
			if err.Error() == "User is not registered" {
				ignore = true
			} else {
				log.Println(err)
			}
		}
		if !ignore {
			WriteErrorString(w, "Not Authorized Request", 401)
			return
		}
	}

	registered, err := auth.CheckRegistered(userID)
	if err != nil {
		WriteError(w, err, 500)
	}

	WriteJson(w, genMap("Registered", registered))
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
		userID, _, err = auth.Login(user, pass, false)
		if err != nil {
			WriteErrorString(w, "Not Authorized Request", 401)
			return
		}
	} else {
		userID, err = auth.GetUserID(user)
		if err != nil {
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

func sendEmail(w http.ResponseWriter, r *http.Request) {
	// Body should have carriage returns
	newEmail := email.Email{
		Recipient: "taifighterm@gmail.com",
		Subject:   "Test email",
		Body:      "asdfsadfsadfasdfasdf",
	}

	err := email.SendMail("www.marktai.com:25", newEmail)
	if err != nil {
		WriteError(w, err, 500)
	}

	w.WriteHeader(200)

}
