package directory

import (
	"fmt"

	"github.com/cvsouth/tor-go/circuit"
)

// FetchConsensus fetches the microdescriptor consensus via a BEGIN_DIR stream
// over the given circuit. The circuit's last hop must support directory requests
// (e.g., a directory authority).
func FetchConsensus(circ *circuit.Circuit) (string, error) {
	body, err := FetchViaBeginDir(circ, "/tor/status-vote/current/consensus-microdesc", 10*1024*1024)
	if err != nil {
		return "", fmt.Errorf("fetch consensus: %w", err)
	}
	return string(body), nil
}
