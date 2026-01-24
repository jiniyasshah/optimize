package utils

import (
	"fmt"
	"net/smtp"
	"web-app-firewall-ml-detection/internal/config"
)

type EmailSender struct {
	cfg *config.Config
}

func NewEmailSender(cfg *config.Config) *EmailSender {
	return &EmailSender{cfg: cfg}
}

// Send now accepts a 'senderName' parameter
func (s *EmailSender) Send(to, subject, body, senderName string) error {
	// Titan Email supports PlainAuth
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	
	// Construct the dynamic "From" header
	// Format: "Minishield Verification <no-reply@minishield.tech>"
	fromHeader := fmt.Sprintf("%s <%s>", senderName, s.cfg.SMTPUser)

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n\r\n"+
		"%s\r\n", fromHeader, to, subject, body))

	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, s.cfg.SMTPPort)
	
	// SendMail always requires the raw email address for the envelope (authentication)
	return smtp.SendMail(addr, auth, s.cfg.SMTPUser, []string{to}, msg)
}