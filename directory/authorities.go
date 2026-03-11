package directory

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cvsouth/tor-go/descriptor"
)

// DirAuthority represents a Tor directory authority with its identity and network info.
type DirAuthority struct {
	Nickname    string
	Address     string
	ORPort      uint16
	DirPort     uint16
	V3Ident     string   // SHA-1 of RSA identity key, uppercase hex
	Fingerprint [20]byte // SHA-1 of RSA identity key, binary
	Ed25519ID   [32]byte // Ed25519 identity key; zero until populated from live consensus/descriptor
}

// DirAuthorities lists the 9 Tor directory authorities (from C Tor auth_dirs.inc, 2026-03).
// Serge is intentionally excluded: it is a bridge authority (no v3ident), not a directory authority.
var DirAuthorities = []DirAuthority{
	newDirAuthority("moria1", "128.31.0.39", 9201, 9231, "F533C81CEF0BC0267857C99B2F471ADF249FA232"),
	newDirAuthority("tor26", "217.196.147.77", 443, 80, "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C"),
	newDirAuthority("dizum", "45.66.35.11", 443, 80, "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58"),
	newDirAuthority("gabelmoo", "131.188.40.189", 443, 80, "ED03BB616EB2F60BEC80151114BB25CEF515B226"),
	newDirAuthority("dannenberg", "193.23.244.244", 443, 80, "0232AF901C31A04EE9848595AF9BB7620D4C5B2E"),
	newDirAuthority("maatuska", "171.25.193.9", 80, 443, "49015F787433103580E3B66A1707A00E60F2D15B"),
	newDirAuthority("longclaw", "199.58.81.140", 443, 80, "23D15D965BC35114467363C165C4F724B64B4F66"),
	newDirAuthority("bastet", "204.13.164.118", 443, 80, "27102BC123E7AF1D4741AE047E160C91ADC76B21"),
	newDirAuthority("faravahar", "216.218.219.41", 443, 80, "70849B868D606BAECFB6128C5E3D782029AA394F"),
}

func newDirAuthority(nickname, address string, orPort, dirPort uint16, v3ident string) DirAuthority {
	var fp [20]byte
	b, err := hex.DecodeString(v3ident)
	if err != nil {
		panic("invalid v3ident hex for " + nickname + ": " + err.Error())
	}
	copy(fp[:], b)
	return DirAuthority{
		Nickname:    nickname,
		Address:     address,
		ORPort:      orPort,
		DirPort:     dirPort,
		V3Ident:     v3ident,
		Fingerprint: fp,
	}
}

// DirAddr returns "address:dirport" for the given authority.
func (a *DirAuthority) DirAddr() string {
	return fmt.Sprintf("%s:%d", a.Address, a.DirPort)
}

// maxDescriptorBytes is the upper bound on authority descriptor size (256 KB).
const maxDescriptorBytes = 256 * 1024

// FetchAuthorityDescriptor fetches the server descriptor for a directory
// authority via plaintext HTTP and returns the parsed RelayInfo (including
// NodeID and ntor-onion-key). The descriptor is fully parsed and
// RSA-signature-verified using descriptor.ParseDescriptor for defense-in-depth.
//
// Trust model: the descriptor is fetched over plaintext HTTP, so a MITM could
// serve a valid-but-wrong descriptor signed by a different relay's RSA key.
// A fingerprint cross-check is not possible here because V3Ident (the
// authority's voting key fingerprint) differs from the relay identity
// fingerprint in the server descriptor — authorities have two distinct RSA keys.
// However, the subsequent BootstrapCircuit performs an ntor handshake using the
// relay identity from this descriptor, and the TLS CERTS handshake validates
// the full certificate chain. A MITM would therefore need to control a relay
// with a valid RSA signing key AND complete the ntor handshake, which requires
// possession of the corresponding private key.
func FetchAuthorityDescriptor(auth *DirAuthority) (*descriptor.RelayInfo, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
		},
		// Directory authorities never redirect; reject redirects to prevent
		// SSRF via a MITM on the plaintext HTTP connection.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("http://%s:%d/tor/server/authority", auth.Address, auth.DirPort)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch descriptor from %s: %w", auth.Nickname, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch descriptor from %s: HTTP %d", auth.Nickname, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDescriptorBytes))
	if err != nil {
		return nil, fmt.Errorf("read descriptor from %s: %w", auth.Nickname, err)
	}

	info, err := descriptor.ParseDescriptor(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse descriptor from %s: %w", auth.Nickname, err)
	}

	return info, nil
}
