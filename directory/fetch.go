package directory

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// Directory authorities (from tor source, as of 2025).
var DirAuthorities = []string{
	"128.31.0.39:9131",   // moria1
	"86.59.21.38:80",     // tor26
	"194.109.206.212:80", // dizum
	"199.58.81.140:80",   // Faravahar
	"204.13.164.118:80",  // longclaw
	"66.111.2.131:9030",  // bastet
	"193.23.244.244:80",  // dannenberg
	"171.25.193.9:443",   // maatuska
	"154.35.175.225:80",  // gabelmoo
}

// FetchConsensus fetches the microdescriptor consensus from directory authorities.
// It tries each authority in order until one succeeds.
func FetchConsensus() (string, error) {
	var lastErr error
	for _, addr := range DirAuthorities {
		body, err := fetchConsensusFrom(addr)
		if err != nil {
			lastErr = err
			continue
		}
		return body, nil
	}
	return "", fmt.Errorf("all directory authorities failed, last error: %w", lastErr)
}

// FetchConsensusFrom fetches the microdescriptor consensus from a specific directory authority.
func FetchConsensusFrom(addr string) (string, error) {
	return fetchConsensusFrom(addr)
}

func fetchConsensusFrom(addr string) (string, error) {
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true, // Tor directory servers mishandle Accept-Encoding
		},
	}
	url := fmt.Sprintf("http://%s/tor/status-vote/current/consensus-microdesc", addr)

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch consensus from %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch consensus from %s: HTTP %d", addr, resp.StatusCode)
	}

	// Consensus is typically ~2MB, cap at 10MB for safety
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", fmt.Errorf("read consensus from %s: %w", addr, err)
	}

	return string(body), nil
}
