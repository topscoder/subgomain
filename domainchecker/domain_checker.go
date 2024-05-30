package domainchecker

import (
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/topscoder/subgomain/fingerprints"
)

// CheckDomain checks if the given domain is vulnerable based on the fingerprints.
func CheckDomain(domain string, fingerprints []fingerprints.Fingerprint) (bool, error) {
	// Check DNS
	cname, err := net.LookupCNAME(domain)
	if err == nil {
		for _, fp := range fingerprints {
			for _, cnameEntry := range fp.CNAME {
				if strings.Contains(cname, cnameEntry) {
					return true, nil
				}
			}
		}
	}

	// Check HTTP response
	resp, err := http.Get("http://" + domain)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	for _, fp := range fingerprints {
		if fp.HTTPStatus != nil && resp.StatusCode == *fp.HTTPStatus {
			for _, fingerprint := range fp.Fingerprint {
				if strings.Contains(string(body), fingerprint) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
