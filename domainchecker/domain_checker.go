package domainchecker

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/topscoder/subgomain/fingerprints"
)

// ResolverIndex keeps track of the current resolver index
var ResolverIndex int

// initializeResolverIndex initializes ResolverIndex with a random value
func initializeResolverIndex(resolvers []string) {
	rand.Seed(time.Now().UnixNano())
	ResolverIndex = rand.Intn(len(resolvers))
}

// rotateResolver rotates to the next resolver
func rotateResolver(resolvers []string) string {
	resolver := resolvers[ResolverIndex]
	ResolverIndex = (ResolverIndex + 1) % len(resolvers)
	return resolver
}

// CheckDomain checks if the given domain is vulnerable based on the fingerprints.
func CheckDomain(domain string, fingerprints []fingerprints.Fingerprint, resolvers []string, httpTimeout time.Duration) (bool, *fingerprints.Fingerprint, string, error) {
	// Initialize ResolverIndex with a random value on the first call
	if ResolverIndex == 0 {
		initializeResolverIndex(resolvers)
	}

	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	// Rotate resolver
	resolverAddress := rotateResolver(resolvers) + ":53"

	// Create a resolver with the context
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", resolverAddress)
		},
	}

	// Check CNAME with timeout
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return false, nil, "", err
	}

	if cname != "" {
		for _, fp := range fingerprints {
			for _, cnameEntry := range fp.CNAME {
				if cnameEntry != "" && strings.Contains(cname, cnameEntry) {
					return true, &fp, "CNAME", nil
				}
			}
		}
	}

	// Check A record with timeout
	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return false, nil, "", err
	}

	for _, ip := range ips {
		for _, fp := range fingerprints {
			for _, aRecord := range fp.A {
				if aRecord != "" && aRecord == ip.String() {
					return true, &fp, "A-record", nil
				}
			}
		}
	}

	// Create a custom HTTP transport that skips SSL/TLS certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Transport: tr,
		Timeout:   httpTimeout,
	}

	// Make HTTPS GET request with timeout
	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		return false, nil, "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, "", err
	}

	for _, fp := range fingerprints {
		for _, fingerprint := range fp.Fingerprint {
			if fingerprint != "" && strings.Contains(string(body), fingerprint) {
				return true, &fp, "Fingerprint", nil
			}
		}
	}

	return false, nil, "", nil
}
