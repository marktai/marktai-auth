package auth

import (
	"db"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const BADCHARS = "[^a-zA-Z0-9_]"

func extractStringFromHeader(r *http.Request, key string) (string, error) {
	strSlice, ok := r.Header[key]
	if !ok || strSlice == nil || len(strSlice) == 0 {
		return "", errors.New("No " + key + " header provided")
	}
	return strSlice[0], nil
}

func extractIntFromHeader(r *http.Request, key string) (int, error) {
	s, err := extractStringFromHeader(r, key)
	if err != nil {
		return 0, err
	}
	retInt, err := strconv.Atoi(s)
	return retInt, err
}

func extractUintFromHeader(r *http.Request, key string) (uint, error) {
	retInt, err := extractIntFromHeader(r, key)
	return uint(retInt), err
}

func stringtoUint(s string) (uint, error) {
	i, err := strconv.Atoi(s)
	return uint(i), err
}

// checks if user id conflict in database
func checkIDConflict(id uint) (bool, error) {
	collision := 1
	err := db.Db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE userid=?)", id).Scan(&collision)
	return collision != 0, err
}

// returns a unique id for a user
func getUniqueID() (uint, error) {

	var count uint
	var scale uint
	var addConst uint

	var newID uint

	err := db.Db.QueryRow("SELECT count, scale, addConst FROM count WHERE type='users'").Scan(&count, &scale, &addConst)
	if err != nil {
		return 0, err
	}

	conflict := true
	for conflict || newID == 0 {
		count += 1
		newID = (count*scale + addConst) % 65536

		conflict, err = checkIDConflict(newID)
		if err != nil {
			return 0, err
		}
	}

	updateCount, err := db.Db.Prepare("UPDATE count SET count=? WHERE type='users'")
	if err != nil {
		return newID, err
	}

	_, err = updateCount.Exec(count)
	if err != nil {
		return newID, err
	}

	return newID, nil
}

// returns the userid of a user
func GetUserID(user string) (uint, error) {
	var userID uint
	if bad, err := regexp.MatchString(BADCHARS, user); err != nil {
		return 0, err
	} else if bad {
		return 0, errors.New("Invalid user name")
	}
	err := db.Db.QueryRow("SELECT userid FROM users WHERE name=?", user).Scan(&userID)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

// returns the username of a user
func GetUsername(userID uint) (string, error) {
	var username string

	err := db.Db.QueryRow("SELECT name FROM users WHERE userid=?", userID).Scan(&username)
	if err != nil {
		return "", err
	}

	return username, nil
}

// makes a new user and returns its id
func MakeUser(user, pass string) (uint, error) {

	// username santization in GetUserID
	userID, err := GetUserID(user)
	if err != nil && err.Error() != "sql: no rows in result set" {
		// if there is an error
		// does not include error when user is not found
		return 0, err
	} else if userID != 0 {
		return 0, errors.New("User already made")
	}

	id, err := getUniqueID()
	if err != nil {
		return 0, err
	}

	saltHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	saltHashString := base64.StdEncoding.EncodeToString(saltHash)

	err = db.Db.Ping()
	if err != nil {
		return 0, err
	}

	addUser, err := db.Db.Prepare("INSERT INTO users (userid, name, salthash) VALUES(?, ?, ?)")
	if err != nil {
		return 0, err
	}

	_, err = addUser.Exec(id, user, saltHashString)

	if err != nil {
		return 0, err
	}

	return id, nil
}

func ChangePassword(userid uint, pass string) error {
	saltHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	saltHashString := base64.StdEncoding.EncodeToString(saltHash)

	changePass, err := db.Db.Prepare("UPDATE users set salthash=? where userid=?")
	if err != nil {
		return err
	}

	_, err = changePass.Exec(saltHashString, userid)
	return err
}

// returns the salthash of a user
func getSaltHash(userID uint) ([]byte, error) {
	saltHashString := ""
	err := db.Db.QueryRow("SELECT salthash FROM users WHERE userid=?", userID).Scan(&saltHashString)
	if err != nil {
		return nil, err
	}
	saltHash, err := base64.StdEncoding.DecodeString(saltHashString)
	return saltHash, err
}

// if a successful login, generates a secret or refreshes the existing one
func Login(user, pass string) (uint, *Secret, error) {

	// username santization in GetUserID
	userID, err := GetUserID(user)
	if err != nil {
		return 0, nil, err
	}

	hash, err := getSaltHash(userID)
	if err != nil {
		return 0, nil, err
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(pass))

	if err != nil {
		return 0, nil, err
	}

	if _, ok := secretMap[userID]; !ok || secretMap[userID].Expired() {
		secret, err := newSecret()
		if err != nil {
			return 0, nil, err
		}
		secretMap[userID] = secret
	}

	secretMap[userID].resetExpiration()

	return userID, secretMap[userID], nil
}

// if the user and secret are correct, refreshes the secret
func VerifySecret(user, inpSecret string) (uint, *Secret, error) {

	// username santization in GetUserID
	userID, err := GetUserID(user)
	if err != nil {
		return 0, nil, err
	}

	if _, ok := secretMap[userID]; !ok {
		return 0, nil, errors.New("No secret found for user")
	} else if secretMap[userID].Expired() {
		return 0, nil, errors.New("Secret has expired")
	} else if secretMap[userID].String() != inpSecret {
		return 0, nil, errors.New("Secrets do not match")
	}

	secretMap[userID].resetExpiration()

	return userID, secretMap[userID], nil
}

// returns userID, message used to generate HMAC, and HMAC from request
func parseRequestHeaders(r *http.Request) (uint, int, string, []byte, error) {
	userID, err := extractUintFromHeader(r, "Userid")
	if err != nil {
		return 0, 0, "", nil, err
	}

	timeInt, err := extractIntFromHeader(r, "Time-Sent")
	if err != nil {
		return 0, 0, "", nil, err
	}

	path, err := extractStringFromHeader(r, "Path")
	if err != nil {
		return 0, 0, "", nil, err
	}

	messageHMACString, err := extractStringFromHeader(r, "Hmac")
	if err != nil {
		return 0, 0, "", nil, err
	}

	encoding, err := extractStringFromHeader(r, "Encoding")
	if err != nil {
		encoding = "hex"
	}

	HMACEncoding := ""
	switch strings.ToLower(encoding) {
	case "base64", "64":
		HMACEncoding = "base64"
	case "hex", "hexadecimal":
		HMACEncoding = "hex"
	case "binary", "bits":
		HMACEncoding = "binary"
	case "decimal":
		HMACEncoding = "decimal"
	default:
		HMACEncoding = encoding
	}

	var messageHMAC []byte
	switch HMACEncoding {
	case "base64":
		messageHMAC, err = base64.StdEncoding.DecodeString(messageHMACString)
	case "hex":
		messageHMAC, err = hex.DecodeString(messageHMACString)
	default:
		return 0, 0, "", nil, errors.New("'" + HMACEncoding + "' not a supported encoding")
	}

	if err != nil {
		return 0, 0, "", nil, err
	}

	return userID, timeInt, path, messageHMAC, nil
}

// Check README.md for documentation
// Request Headers
// UserID - ID of user to authenticate
// Path - path of endpoint requested
// HMAC - encoded HMAC with SHA 256
// Encoding - encoding format (default hex)
// Time-Sent - seconds since epoch

// Verifies whether a request is correctly authorized
func AuthRequestHeaders(r *http.Request) (bool, error) {
	userID, timeInt, path, messageHMAC, err := parseRequestHeaders(r)
	if err != nil {
		return false, err
	}

	return AuthParams(userID, timeInt, path, messageHMAC)
}

func AuthParams(userID uint, timeInt int, path string, messageHMAC []byte) (bool, error) {

	message := fmt.Sprintf("%d:%s", timeInt, path)
	delay := int64(timeInt) - time.Now().Unix()

	// rejects if times are more than 30 seconds apart
	// used to be 10, but sometimes had authentication rejects because of it
	if delay < -30 || delay > 30 {
		return false, errors.New("Time difference too large")
	}

	secret, ok := secretMap[userID]
	if !ok {
		return false, errors.New("No secret for that user")
	}

	if secret.Expired() {
		return false, errors.New("Secret expired")
	}

	secretString := secret.String()
	return checkMAC(secretString, message, messageHMAC), nil
}
