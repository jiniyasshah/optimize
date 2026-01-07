package logger

import (
	"web-app-firewall-ml-detection/internal/core"
)

var broadcast = make(chan core.AttackLog, 100)

// GetBroadcastChannel is used by the SSE Handler to stream logs to the frontend
func GetBroadcastChannel() chan core.AttackLog {
	return broadcast
}

// LogAttack sends the log entry to the broadcast channel.
func LogAttack(entry core.AttackLog) {
	select {
	case broadcast <- entry:
	default:
		// we drop the message to keep the WAF fast.
	}
}