package logger

import (
	"sync"
	"web-app-firewall-ml-detection/internal/core"
)

// Broker manages the list of active SSE clients
type Broker struct {
	mu          sync.RWMutex // Read/Write lock for thread safety
	subscribers map[chan core.AttackLog]struct{}
}

// Global broker instance
var broker = &Broker{
	subscribers: make(map[chan core.AttackLog]struct{}),
}

// creates a new dedicated channel for a client
func Subscribe() chan core.AttackLog {
	broker.mu.Lock()
	defer broker.mu.Unlock()

	// Buffer of 50 prevents minor network lag from dropping logs
	ch := make(chan core.AttackLog, 50)
	broker.subscribers[ch] = struct{}{}
	return ch
}

//  removes a client and closes their channel
func Unsubscribe(ch chan core.AttackLog) {
	broker.mu.Lock()
	defer broker.mu.Unlock()

	if _, ok := broker.subscribers[ch]; ok {
		delete(broker.subscribers, ch)
		close(ch) 
	}
}

// broadcasts a log entry to ALL active subscribers
func LogAttack(entry core.AttackLog) {
	broker.mu.RLock() // concurrent broadcasting
	defer broker.mu.RUnlock()

	for ch := range broker.subscribers {
		select {
		case ch <- entry:
			// Message sent successfully
		default:
			// Drop message for slower clients to protect the WAF from blocking.
		}
	}
}

