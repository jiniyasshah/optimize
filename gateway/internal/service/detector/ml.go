package detector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type MLRequest struct {
	Path    string            `json:"path"`
	Body    string            `json:"body"`
	Length  int               `json:"length"`
	Headers map[string]string `json:"headers"`
}

type MLResponse struct {
	IsAnomaly      bool    `json:"is_anomaly"`
	AnomalyScore   float64 `json:"anomaly_score"`
	AttackType     string  `json:"attack_type"`
	TriggerContent string  `json:"trigger_content"`
}

func CheckML(r *http.Request, bodyBytes []byte, mlURL string) (bool, float64, string, string) {
	if mlURL == "" {
		return false, 0.0, "", ""
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = v[0]
	}

	payload := MLRequest{
		Path:    r.URL.Path + "?" + r.URL.RawQuery,
		Body:    string(bodyBytes),
		Length:  len(bodyBytes),
		Headers: headers,
	}

	jsonData, _ := json.Marshal(payload)
	client := http.Client{Timeout: 800 * time.Millisecond} // Strict timeout

	resp, err := client.Post(mlURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, 0.0, "ML_Error", ""
	}
	defer resp.Body.Close()

	var result MLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, 0.0, "ML_Error", ""
	}

	return result.IsAnomaly, result.AnomalyScore, result.AttackType, result.TriggerContent
}