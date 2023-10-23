package email

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/mail"
	"net/smtp"
)

var passwords = make(map[string]string)

// Body should have carriage returns
type Email struct {
	Sender         string
	SenderAlias    string
	Recipient      string
	RecipientAlias string
	Subject        string
	Body           string
}

func readPasswords(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, &passwords)
	if err != nil {
		return err
	}

	return nil
}

func SendMail(mailserver string, e Email) error {
	if e.Sender == "" {
		e.Sender = "email_bot@marktai.com"
	}

	from := mail.Address{e.SenderAlias, e.Sender}
	to := mail.Address{e.RecipientAlias, e.Recipient}

	// Setup headers
	headers := make(map[string]string)
	headers["From"] = from.String()
	headers["To"] = to.String()
	headers["Subject"] = e.Subject

	// Setup message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + e.Body

	// Connect to the SMTP Server
	servername := mailserver

	host, _, err := net.SplitHostPort(servername)
	if err != nil {
		return err
	}

	password := ""
	var ok bool
	if password, ok = passwords[e.Sender]; !ok {
		err := readPasswords("creds/email.json")
		if err != nil {
			return err
		}
		if password, ok = passwords[e.Sender]; !ok {
			return errors.New(fmt.Sprintf("%s not in creds/email.json", e.Sender))
		}
	}

	auth := smtp.PlainAuth("", e.Sender, password, host)

	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	// Here is the key, you need to call tls.Dial instead of smtp.Dial
	// for smtp servers running on 465 that require an ssl connection
	// from the very beginning (no starttls)
	// conn, err := tls.Dial("tcp", servername, tlsconfig)
	// if err != nil {
	// 	return err
	// }

	// c, err := smtp.NewClient(conn, host)
	// if err != nil {
	// 	return err
	// }

	// create the smtp connection
	c, err := smtp.Dial(mailserver)
	if err != nil {
		return err
	}

	if err = c.StartTLS(tlsconfig); err != nil {
		return err
	}

	// Auth
	if err = c.Auth(auth); err != nil {
		return err
	}

	// To && From
	if err = c.Mail(from.Address); err != nil {
		return err
	}

	if err = c.Rcpt(to.Address); err != nil {
		return err
	}

	// Data
	w, err := c.Data()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	c.Quit()
	return nil
}
