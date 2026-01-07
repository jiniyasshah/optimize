package logger

import (
	"sync"
	"web-app-firewall-ml-detection/internal/core"
)

// Broker manages multiple SSE subscribers
type Broker struct {
	mu          sync.Mutex
	subscribers map[chan core.AttackLog]struct{}
}

// Global broker instance
var broker = &Broker{
	subscribers: make(map[chan core.AttackLog]struct{}),
}

// Subscribe creates a new channel for a client and registers it
func Subscribe() chan core.AttackLog {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	
	// Create a buffered channel for this specific client
	ch := make(chan core.AttackLog, 100) 
	broker.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a client and closes their channel
func Unsubscribe(ch chan core.AttackLog) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	
	if _, ok := broker.subscribers[ch]; ok {
		delete(broker.subscribers, ch)
		close(ch)
	}
}

// LogAttack broadcasts the log entry to ALL active subscribers
func LogAttack(entry core.AttackLog) {
	broker.mu.Lock()
	defer broker.mu.Unlock()

	for ch := range broker.subscribers {
		select {
		case ch <- entry:
			// Message sent successfully
		default:
			// Client buffer is full (too slow), skip this message for them 
			// to prevent blocking the entire WAF.
		}
	}
}

