# Code Examples in Security/Networking Go Library READMEs

Research date: 2026-02-17

## Evidence Gathered

### Project-by-project analysis

**bine (cretz/bine) -- closest comparable project (Go Tor library)**
- Includes a single ~50-line Go code example in the README
- Shows creating a v3 onion service that serves the current directory via HTTP
- Introduced with: "It is really easy to create an onion service. For example..."
- The example is a complete, copy-pasteable `main()` function
- Key design choice: shows the *highest-value use case* (onion services), not the simplest possible call
- A secondary 1-line snippet shows how to swap in an embedded Tor binary
- No CLI usage examples -- bine is library-only

**age (FiloSottile/age) -- crypto tool with library**
- All examples are shell commands, not Go code
- Examples use `$` shell prompts with expected output shown inline
- Organized by use case: basic workflow, multiple recipients, passphrases, SSH keys, etc.
- Each example is 1-4 lines of shell commands
- Progressive disclosure: simplest case first, advanced cases later
- The library API is not shown at all; users are directed to godoc

**mkcert (FiloSottile/mkcert) -- crypto tool**
- Two shell commands shown immediately after the one-line description
- Shows output including success messages to make the result feel tangible
- The "demo before explanation" pattern: install CA, create cert, done
- No Go code at all (mkcert is a tool, not a library)
- Advanced usage is a list of flags, not code

**kcp-go (xtaci/kcp-go) -- networking library**
- No inline code examples in the README
- Points to a separate examples folder and to godoc
- Uses architecture diagrams and benchmark results instead
- The README is a technical reference, not a tutorial

**wireguard-go (from Q1 findings)**
- All code blocks are shell commands (`go build`, platform-specific invocations)
- Zero Go API code in the README
- The project positions itself as a tool you build and run, not a library you import

### Pattern summary

| Project | Go code example? | Shell examples? | Example length | Shows highest-value use case? |
|---------|-------------------|-----------------|---------------|-------------------------------|
| bine | Yes, 1 example | No | ~50 lines | Yes (onion service) |
| age | No | Yes, many | 1-4 lines each | Yes (encrypt/decrypt) |
| mkcert | No | Yes, 2 commands | 2 lines | Yes (create cert) |
| kcp-go | No | No | N/A | N/A (defers to godoc) |
| wireguard-go | No | Yes | 1-2 lines each | Yes (build & run) |

---

## Analysis for tor-go

### The fundamental tension

tor-go has a problem none of the above projects face to the same degree: the minimal working example for the library API is genuinely complex. Looking at `cmd/tor-client/main.go`, even a stripped-down version requires:

1. Fetch consensus (~10 lines with caching/error handling)
2. Fetch microdescriptors (~15 lines)
3. Select path (~3 lines)
4. Connect to guard + create circuit (~8 lines)
5. Extend to middle and exit (~6 lines)
6. Open a stream or start a SOCKS proxy (~5 lines)

That is roughly 50-70 lines minimum for a working Go example, and unlike bine's example, each step involves a different package. This is inherent complexity, not accidental complexity -- the library faithfully exposes the Tor protocol rather than hiding it behind a facade.

### Recommendation: Lead with CLI, follow with Go code

**Primary example: Shell (CLI tool)**

```
go install github.com/cvsouth/tor-go/cmd/tor-client@latest
tor-client
# Ready. Use: curl --socks5-hostname 127.0.0.1:9050 http://example.com
```

This follows the mkcert/age pattern: show the tool working in 2-3 lines. The developer sees immediate value. It answers "what does this do?" before "how does it work?"

Add a verification command to make the result tangible (like mkcert showing output):

```
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"..."}
```

**Secondary example: Go API**

Show a focused ~25-line example that demonstrates the most impressive capability. Two candidates:

*Option A: Minimal clearnet request through Tor* -- Shows the core value (anonymous HTTP) but requires all the setup steps, making it long.

*Option B: Connecting to a .onion service* -- This is the "wow" feature (like bine chose). But it is even more complex than option A.

*Option C (recommended): Abbreviated Go example with comments as placeholders*

```go
// Fetch network consensus and relay descriptors
consensus, _ := directory.FetchAndParse()

// Select a 3-hop path through the Tor network
path, _ := pathselect.SelectPath(consensus)

// Build an encrypted circuit: you <-> guard <-> middle <-> exit
circ, _ := circuit.BuildPath(path)

// Open a TCP stream to any destination through the circuit
stream, _ := circ.OpenStream("example.com", 80)
```

This is a *design aspiration*, not current API. The actual API is more verbose. But it reveals an important insight: **if the README example feels too long, that is a signal that the library might benefit from a convenience layer.** Several projects (including bine) solve this by providing a high-level `Start()` or `Dial()` function that wraps the low-level steps.

### Key findings

1. **CLI first, API second.** Every successful project that has both a CLI tool and a library API leads with the CLI. The CLI example is always shorter and more compelling. tor-go should follow this pattern.

2. **Ideal Go example length: 15-30 lines.** bine's 50-line example is at the upper bound of what works. Most developers will not read past 30 lines of example code in a README. If the example must be longer, it belongs in an `examples/` directory or godoc.

3. **Show the highest-value use case, not the simplest API call.** bine shows onion services, not "connect to a relay." age shows encryption, not key parsing. The example should demonstrate what makes the library worth using.

4. **Show output to make the result tangible.** mkcert and age both show terminal output after commands. For tor-go, showing `{"IsTor":true}` from the Tor check API makes the result concrete and satisfying.

5. **Consider adding a convenience API.** If the minimal Go example is 50+ lines, that is a usability problem, not just a documentation problem. A function like `torgo.Dial("tcp", "example.com:80")` or `torgo.ListenAndServe(":9050")` that handles consensus/path/circuit internally would make both the README and the library more accessible. This is how bine solves it (`tor.Start()` + `tor.Listen()`), and it is the single most impactful thing tor-go could do for developer adoption.

6. **Error handling in examples.** In README examples, using `log.Fatal(err)` or even ignoring errors (with a note) is acceptable. Full `if err != nil` blocks on every call inflate the example and obscure the flow. The Go community accepts abbreviated error handling in README snippets.

### Proposed README structure for the code example section

```
## Quick Start

### CLI

[2-3 shell lines: install, run, curl test]

### Library

[15-25 line Go example OR link to examples/ directory]

For detailed API documentation, see [pkg.go.dev link].
```

This mirrors the age/mkcert pattern (shell first), adds a focused Go snippet like bine, and defers the full details to godoc like kcp-go and wireguard-go.
