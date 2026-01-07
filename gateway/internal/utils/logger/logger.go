package logger

import (
	"web-app-firewall-ml-detection/internal/core"
)

// This holds the logs for the SSE stream
var broadcast = make(chan core.AttackLog, 100)

// GetBroadcastChannel returns the read-only channel
func GetBroadcastChannel() chan core.AttackLog {
	return broadcast
}

func LogAttack(entry core.AttackLog) {
	select {
	case broadcast <- entry:
		// Pushed to channel
	default:
		// Channel full, drop to prevent blocking
	}
}