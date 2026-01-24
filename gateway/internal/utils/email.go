package utils

import (
	"crypto/tls"
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

func (s *EmailSender) Send(to, subject, body, senderName string) error {
	// 1. Setup Headers
	fromHeader := fmt.Sprintf("%s <%s>", senderName, s.cfg.SMTPUser)
	
	// Headers must include From, To, Subject, and MIME info for HTML
	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n\r\n"+
		"%s\r\n", fromHeader, to, subject, body))

	// 2. Define Server Address (Force Port 465)
	// We ignore s.cfg.SMTPPort if you want to hardcode, or ensure config is 465
	addr := s.cfg.SMTPHost + ":465"

	// 3. Create TLS Configuration
	// ServerName is critical for certificate validation
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, 
		ServerName:         s.cfg.SMTPHost,
	}

	// 4. Dial using TLS (Implicit SSL)
	// This is the key difference from standard smtp.SendMail
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to dial tls: %v", err)
	}
	defer conn.Close()

	// 5. Create SMTP Client over the TLS connection
	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create smtp client: %v", err)
	}
	defer client.Quit()

	// 6. Authenticate
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("auth failed: %v", err)
	}

	// 7. Send Email
	if err = client.Mail(s.cfg.SMTPUser); err != nil {
		return fmt.Errorf("mail command failed: %v", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt command failed: %v", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data command failed: %v", err)
	}
	
	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("close failed: %v", err)
	}

	return nil
}