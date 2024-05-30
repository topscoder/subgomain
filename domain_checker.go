package domainchecker

import (
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/topscoder/subgomain/fingerprints"
)

func CheckDomain(domain string, fingerprints []fingerprints.Fingerprint) (bool, error) {
	// Check DNS
	cname, err := net.LookupCNAME(domain)
	if err == nil {
		for _, fp := range fingerprints {
			if strings.Contains(cname, fp.CNAME) {
				return true, nil
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
		if resp.StatusCode == fp.Status && strings.Contains(string(body), fp.Content) {
			return true, nil
		}
	}

	return false, nil
}
