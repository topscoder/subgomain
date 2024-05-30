package fingerprints

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type Fingerprint struct {
	// Define the structure based on the JSON file
	Service string `json:"service"`
	CNAME   string `json:"cname"`
	Status  int    `json:"status"`
	Content string `json:"content"`
}

func LoadFingerprints(url string) ([]Fingerprint, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var fingerprints []Fingerprint
	err = json.Unmarshal(body, &fingerprints)
	if err != nil {
		return nil, err
	}

	return fingerprints, nil
}
