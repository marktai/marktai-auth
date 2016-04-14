package recaptcha

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

var recaptchaSecret string

type siteverifyResp struct {
	Success      bool
	Challenge_ts string
	Hostname     string
}

func ReadSecret(path, key string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	parsedJson := make(map[string]string)
	err = json.Unmarshal(content, &parsedJson)
	if err != nil {
		return err
	}

	if secret, ok := parsedJson[key]; !ok {
		return errors.New("Recaptcha secret for \"www.marktai.com\" not found in " + path)
	} else {
		recaptchaSecret = secret
	}

	return nil
}

func Verify(recaptchaResponse string) (bool, time.Time, string, error) {

	var verified bool
	var timestamp time.Time
	var domain string
	var err error

	urlString := fmt.Sprintf("https://www.google.com/recaptcha/api/siteverify?secret=%s&response=%s", recaptchaSecret, recaptchaResponse)

	log.Println(urlString)

	resp, err := http.Post(urlString, "", nil)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return verified, timestamp, domain, err
	}

	decoder := json.NewDecoder(resp.Body)

	var verification siteverifyResp
	err = decoder.Decode(&verification)
	if err != nil {
		return verified, timestamp, domain, err
	}

	verified = verification.Success
	timestamp, _ = time.Parse(time.RFC3339, verification.Challenge_ts) // I trust Google to not fuck up their timestamp
	domain = verification.Hostname

	return verified, timestamp, domain, nil
}
