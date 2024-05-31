package fingerprints

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Fingerprint represents a single fingerprint entry.
type Fingerprint struct {
	CNAME       []string `json:"cname"`
	A           []string `json:"a"`
	Fingerprint []string `json:"-"`
	HTTPStatus  *int     `json:"http_status"`
	Service     string   `json:"service"`
	Status      string   `json:"status"`
	Vulnerable  bool     `json:"vulnerable"`
}

// UnmarshalJSON handles the custom unmarshalling of the Fingerprint struct.
func (f *Fingerprint) UnmarshalJSON(data []byte) error {
	type Alias Fingerprint
	aux := &struct {
		Fingerprint interface{} `json:"fingerprint"`
		*Alias
	}{
		Alias: (*Alias)(f),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch v := aux.Fingerprint.(type) {
	case string:
		f.Fingerprint = []string{v}
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				f.Fingerprint = append(f.Fingerprint, str)
			}
		}
	}

	return nil
}

// LoadFingerprints loads the fingerprints from the given URL.
func LoadFingerprints(url string) ([]Fingerprint, error) {
	fmt.Println("[INF] Downloading the fingerprints JSON file from " + url)
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

// LoadFingerprintsFromFile loads the fingerprints from a local file.
func LoadFingerprintsFromFile(filePath string) ([]Fingerprint, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var fingerprints []Fingerprint
	err = json.Unmarshal(data, &fingerprints)
	if err != nil {
		return nil, err
	}

	return fingerprints, nil
}
