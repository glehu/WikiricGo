package main

import (
	"errors"
	"fmt"
	"net/smtp"
)

type EmailClient struct {
	Config Config
}

func GetEmailClient(config Config) (*EmailClient, error) {
	if config.EmailFrom == "" || config.EmailHost == "" || config.EmailPass == "" || config.EmailPort == "" {
		return nil, errors.New("EmailFrom EmailHost EmailPass EmailPort cannot be empty")
	}
	return &EmailClient{Config: config}, nil
}

func (client *EmailClient) sendMail(to []string, subject []byte, message []byte) error {
	if client == nil {
		return nil
	}
	if len(to) < 1 || len(message) < 1 {
		return errors.New("to and message cannot be empty")
	}
	// Construct authentication
	auth := smtp.PlainAuth(
		"", client.Config.EmailFrom, client.Config.EmailPass, client.Config.EmailHost)
	// Construct email
	mime := "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\""
	emailPayload := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n%s\r\n\r<html><body>\n%s</body></html>",
		client.Config.EmailFrom, to[0], subject, mime, message,
	))
	// Send email
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s",
			client.Config.EmailHost, client.Config.EmailPort),
		auth, client.Config.EmailFrom, to, emailPayload)
	return err
}
