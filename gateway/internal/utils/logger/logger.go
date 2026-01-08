package logger

import (
	"web-app-firewall-ml-detection/internal/detector" // Imported and USED now

	"go.mongodb.org/mongo-driver/mongo"
)

// [DELETED] FullRequest and AttackLog structs are removed from here.
// They are now imported from "web-app-firewall-ml-detection/internal/detector"

var logCollection *mongo.Collection

// [UPDATED] Use detector.AttackLog
var broadcast = make(chan detector.AttackLog, 100)

func Init(client *mongo.Client, dbName string) {
	logCollection = client.Database(dbName).Collection("logs")
}

// [UPDATED] Use detector.AttackLog
func GetBroadcastChannel() chan detector.AttackLog {
	return broadcast
}
