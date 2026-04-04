package alerts

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
)

// SendEmail sends an alert email for a critical/warning event.
func SendEmail(cfg *config.SMTPConfig, event *db.Event) error {
	if cfg.Host == "" || len(cfg.To) == 0 {
		return nil
	}

	subject := fmt.Sprintf("[MythNet %s] %s", strings.ToUpper(event.Severity), event.Title)

	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n",
		cfg.From, strings.Join(cfg.To, ", "), subject)

	body += fmt.Sprintf("Severity: %s\nSource: %s\nTime: %s\n\n",
		event.Severity, event.Source, event.ReceivedAt.Format("2006-01-02 15:04:05"))
	body += event.Title + "\n\n"

	// Strip markdown formatting for plain text
	plain := event.BodyMD
	plain = strings.ReplaceAll(plain, "**", "")
	plain = strings.ReplaceAll(plain, "## ", "")
	plain = strings.ReplaceAll(plain, "### ", "")
	plain = strings.ReplaceAll(plain, "```\n", "")
	plain = strings.ReplaceAll(plain, "```", "")
	body += plain
	body += "\n\n---\nSent by MythNet Network Monitor"

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	return smtp.SendMail(addr, auth, cfg.From, cfg.To, []byte(body))
}
