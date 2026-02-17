# Go Library README Structures: Primary Evidence Analysis

Research date: 2026-02-17

## Methodology

Fetched and analyzed the actual README files from 9 popular Go projects spanning networking, crypto, security, and protocol libraries. Projects were selected for relevance to a Go Tor client library.

---

## Per-Project Structural Breakdown

### 1. wireguard-go (WireGuard/wireguard-go)

**Profile:** Pure Go implementation of a networking protocol. Very close analog to tor-go.

**Sections (in order):**
1. H1: "Go Implementation of WireGuard"
2. H2: Usage
3. H2: Platforms (with H3 per platform: Linux, macOS, Windows, FreeBSD, OpenBSD)
4. H2: Building
5. H2: License

**Characteristics:**
- Extremely short (~50 lines of prose)
- Zero badges
- 4 code blocks (all shell commands, no Go code)
- No feature list, no screenshots, no badges
- Opens with a single-sentence description: what it is
- "Pure Go" is implicit in the title, not called out as a selling point
- No installation via `go get` -- it's a standalone binary
- License text is included inline (full MIT license in the README)

**Notable omission:** No API examples, no godoc link, no contributing guide, no CI badges.

---

### 2. age (FiloSottile/age)

**Profile:** Crypto tool + Go library by a well-known Go/crypto developer. Strong analog.

**Sections (in order):**
1. Logo + one-line tagline ("a simple, modern and secure file encryption tool, format, and Go library")
2. 3 badges (Go Reference, man page, C2SP spec)
3. H2: Installation (per-platform instructions)
4. H2: Usage (with many H3 subsections: Multiple recipients, Post-quantum keys, Passphrases, SSH keys, etc.)

**Characteristics:**
- ~200 lines of content
- 12+ code blocks (all shell command examples, no Go library code)
- Leads with what it IS in one sentence, then immediately what makes it different (small keys, no config, composability)
- The tagline does triple duty: tool + format + Go library
- Despite being a Go library too, the README focuses entirely on CLI usage
- Go library usage is deferred to godoc (linked via badge)
- "Pure Go" is never mentioned despite being pure Go
- Pronunciation guide for the name (opinionated, memorable)

**Notable omission:** No architecture explanation, no benchmarks, no contributing section, no license section (LICENSE file exists separately).

---

### 3. mkcert (FiloSottile/mkcert)

**Profile:** Developer tool in Go. Same author as age.

**Sections (in order):**
1. H1: mkcert
2. One-line description + "requires no configuration"
3. Hero code block (complete usage demo with output)
4. Screenshot
5. Problem statement paragraph (why this exists)
6. H2: Installation (macOS, Linux, Windows subsections)
7. H2: Supported root stores
8. H2: Advanced topics (with H3 subsections)

**Characteristics:**
- ~250 lines
- Heaviest on installation instructions (~40% of content)
- **Leads with a working demo** before any explanation -- show, don't tell
- The hero code block includes emoji in the output (mimicking real terminal output)
- Problem/solution framing in prose: "Using real CAs is dangerous... self-signed causes errors... managing your own CA involves arcane commands... mkcert solves this"
- Security warning prominently placed (Warning: don't share rootCA-key.pem)

**Notable omission:** No badges, no license section, no contributing guide, no benchmarks.

---

### 4. gost (ginuerzh/gost)

**Profile:** Go tunnel/proxy tool. Networking/security domain.

**Sections (in order):**
1. H1: GO Simple Tunnel
2. 6 badges (GoDoc, Go Report Card, codecov, release, Docker, snap)
3. H2: Features (bullet list, ~15 items with links)
4. Links to wiki, Telegram, Google Groups
5. H2: Installation (binaries, source, Docker, Homebrew, snap)
6. H2: Quick Start (extensive usage examples with diagrams)
7. H2: Encryption (protocol-specific subsections)

**Characteristics:**
- ~500+ lines (longest of the set)
- Primarily in Chinese with English README linked separately
- Very heavy on usage examples (~70% of content is code blocks)
- ASCII diagram images for network topology
- Feature list is a link-heavy bullet list -- each item links to detailed wiki docs
- Community links (Telegram, Google Groups) placed prominently near the top

**Notable omission:** No license section in README, no contributing guide, no benchmarks.

---

### 5. go-ethereum (ethereum/go-ethereum)

**Profile:** Major Go project, protocol implementation. Application, not library.

**Sections (in order):**
1. H2: Go Ethereum (with badges and one-line description)
2. H2: Building the source (requirements, make commands)
3. H2: Executables (table of CLI tools with descriptions)
4. H2: Running geth (Hardware requirements subsection, then usage)
5. H2: Contribution (formatting guidelines, PR process)
6. H2: License

**Characteristics:**
- ~300 lines
- Very structured, almost like a man page
- Hardware requirements section (minimum + recommended specs)
- Executables presented as a definition list
- Contribution guidelines included directly
- Dual license explained (LGPL for library, GPL for binaries)

**Notable omission:** No feature list, no screenshots, no "why use this" section.

---

### 6. syncthing (syncthing/syncthing)

**Profile:** Go application. File sync tool.

**Sections (in order):**
1. Logo
2. 3 badges (license, CII Best Practices, Go Report Card)
3. H2: Goals (numbered priority list with descriptions)
4. H2: Getting Started (one-line + link)
5. H2: Docker
6. H2: Getting in Touch (forum, issues, security reporting)
7. H2: Building (one-line instructions)
8. H2: Signed Releases
9. H2: Documentation (link to external docs site)

**Characteristics:**
- ~80 lines of actual content (very concise)
- **Leads with project philosophy/goals** rather than features or usage
- Goals are explicitly priority-ordered ("Safe From Data Loss" > "Secure" > "Easy to Use" > ...)
- Almost everything links out -- the README is a hub/index, not documentation
- Security vulnerability reporting has its own prominent callout
- Zero code blocks in the README

**Notable omission:** No usage examples, no installation instructions beyond build, no feature list, no API docs.

---

### 7. caddy (caddyserver/caddy)

**Profile:** Go web server. Application with plugin architecture.

**Sections (in order):**
1. Centered logo (with dark/light mode support)
2. Tagline: "Every site on HTTPS"
3. One-line description + navigation links (Releases, Documentation, Get Help)
4. 6+ badges
5. Sponsor section
6. H3: Menu (table of contents)
7. H2: Features (extensive bullet list with links)
8. H2: Install
9. H2: Build from source (dev vs. production subsections)
10. H2: Quick start
11. H2: Overview (architectural description)
12. H2: Full documentation (link)
13. H2: Getting help (commercial support, sponsorship, community)
14. H2: About (project history, trademark notice)

**Characteristics:**
- ~400 lines (longest after gost)
- Most polished/branded of all (dark/light logos, sponsor section, trademark notice)
- Has an explicit table of contents
- Feature list is the most detailed (~20 items with sub-bullets)
- "No external dependencies (not even libc)" -- explicit callout
- "Written in Go, a language with higher memory safety guarantees" -- language as selling point
- Commercial support and sponsorship prominently featured
- Trademark section at the bottom

**Notable pattern:** Caddy is the only one that explicitly sells "no external dependencies" and "written in Go" as features.

---

### 8. quic-go (quic-go/quic-go)

**Profile:** Pure Go protocol library. Closest analog to tor-go as a library.

**Sections (in order):**
1. H1: "A QUIC implementation in pure Go"
2. 4 badges (docs, PkgGoDev, coverage, fuzzing)
3. One paragraph: what RFCs are implemented
4. Bullet list of additional features/extensions
5. Link to webtransport-go
6. Link to documentation site
7. H2: Projects using quic-go (table of 18 projects)
8. H2: Release Policy
9. H2: Contributing
10. H2: License

**Characteristics:**
- ~100 lines
- Zero code examples in the README
- "pure Go" is in the H1 title
- Social proof via "Projects using" table (18 notable adopters)
- All usage docs deferred to external documentation site (quic-go.net)
- RFC compliance listed explicitly as bullet points

**Notable pattern:** For a library, the README is a landing page, not documentation. Code examples live in docs/godoc.

---

### 9. kcp-go (xtaci/kcp-go)

**Profile:** UDP library for Go. Networking library.

**Sections (in order):**
1. Badges (7: GoDoc, license, build, coverage, report card, etc.)
2. H2: Introduction
3. H2: Features (bullet list)
4. H2: Documentation (links)
5. H2: Key Design Considerations (6 subsections on technical choices)
6. H2: Specification (wire format)
7. H2: Performance (benchmarks with tables)
8. H2: Typical Flame Graph (image)
9. H2: Connection Termination
10. H2: FAQ
11. H2: Who is using this?
12. H2: Examples (links)
13. H2: Links

**Characteristics:**
- ~400 lines (most technically detailed)
- Deep technical content: wire format specs, flame graphs, design rationale
- Benchmark tables with specific throughput numbers
- "Who is using this?" social proof section
- The most "academic paper" feeling of all the READMEs
- Features list includes specific performance claims (">5K concurrent connections")

---

## Cross-Project Analysis

### Section Frequency (out of 9 projects)

| Section | Count | Notes |
|---------|-------|-------|
| One-line description / tagline | 9/9 | Always present, always first |
| Installation / Building | 9/9 | Universal |
| Usage / Quick Start | 7/9 | Missing from syncthing, quic-go (both link out) |
| License | 5/9 | Others rely on LICENSE file |
| Features list | 5/9 | caddy, gost, kcp-go, quic-go, age |
| Badges | 6/9 | wireguard-go, mkcert, age (minimal) skip them |
| Contributing | 3/9 | go-ethereum, quic-go, caddy |
| "Who uses this" / Social proof | 3/9 | quic-go, kcp-go, caddy |
| Benchmarks / Performance | 1/9 | Only kcp-go |
| Architecture / Design | 2/9 | kcp-go, caddy |
| Logo / Branding | 4/9 | age, syncthing, caddy, gost |
| Table of contents | 2/9 | caddy, kcp-go |
| External docs link | 6/9 | Most larger projects defer to docs sites |

### Section Order Pattern (consensus)

The most common ordering across all projects:

1. **Name + one-line description** (always first)
2. **Badges** (if present, immediately after title)
3. **What it is / Why it exists** (0-2 paragraphs)
4. **Features** (if present, usually bullet list)
5. **Installation**
6. **Usage / Quick Start**
7. **Advanced topics** (if any)
8. **Contributing / Community**
9. **License**

### Length Distribution

| Project | Approx. Lines | Category |
|---------|--------------|----------|
| wireguard-go | ~50 | Minimal |
| syncthing | ~80 | Minimal |
| quic-go | ~100 | Short |
| age | ~200 | Medium |
| mkcert | ~250 | Medium |
| go-ethereum | ~300 | Medium |
| caddy | ~400 | Long |
| kcp-go | ~400 | Long |
| gost | ~500+ | Long |

**Libraries (quic-go, kcp-go, wireguard-go) tend to be shorter** than applications. The library READMEs act as landing pages pointing to godoc/docs sites.

### Prose-to-Code Ratio

- **wireguard-go:** ~70% prose, 30% code (shell commands only)
- **age:** ~40% prose, 60% code (shell commands only)
- **mkcert:** ~35% prose, 65% code (shell commands, installation heavy)
- **gost:** ~20% prose, 80% code (massive usage example library)
- **go-ethereum:** ~80% prose, 20% code
- **syncthing:** ~100% prose, 0% code
- **caddy:** ~85% prose, 15% code
- **quic-go:** ~100% prose, 0% code
- **kcp-go:** ~60% prose, 40% code (benchmarks, specs)

**Key finding:** None of the library READMEs include Go API code examples in the README itself. They all defer to godoc or external docs.

### How "Pure Go" / "Zero Dependencies" Is Handled

| Project | How they communicate it |
|---------|------------------------|
| wireguard-go | Implicit in "Go Implementation of WireGuard" title |
| age | Not mentioned at all |
| mkcert | Not mentioned |
| quic-go | "A QUIC implementation in pure Go" -- in H1 title |
| kcp-go | Not explicitly stated |
| caddy | "Runs anywhere with **no external dependencies** (not even libc)" in features list |
| go-ethereum | Not mentioned |

**Pattern:** "Pure Go" goes in the title/tagline if mentioned at all. It is never belabored. Caddy is the only project that explicitly sells "no external dependencies" and it does so as one bullet among many features, not as a headline.

### What Successful READMEs Deliberately Omit

1. **No exhaustive API documentation** -- all defer to godoc
2. **No changelog** -- all use GitHub Releases
3. **No CI/build instructions for contributors** -- kept in CONTRIBUTING.md if at all
4. **No comparison tables** with alternatives (none of the 9 do this)
5. **No "why Go"** justification (except Caddy's brief mention)
6. **No roadmap** in the README
7. **No dependency list** -- they let go.mod speak for itself
8. **No animated GIFs** (mkcert has a static screenshot; that's the maximum)

---

## Key Patterns for a Go Tor Client Library

### The "Library README" Archetype (from quic-go, kcp-go, wireguard-go)

Go library READMEs that work well follow this template:

```
# [Name]: [what it is] in [pure] Go

[badges: godoc, build, coverage]

[1-2 sentence description. What protocol/standard it implements.]

[Bullet list of supported RFCs/specs/features]

## Documentation
[Link to godoc and/or docs site]

## Installation
go get [import path]

## [Optional: Quick Example]
[Minimal code block -- but most skip this]

## [Optional: Who Uses This]
[Table of notable adopters]

## Contributing
[Brief or link to CONTRIBUTING.md]

## License
[One line + link]
```

### Specific Recommendations for tor-go

1. **Title format:** "Pure Go Tor Client Library" or "A Tor client implementation in pure Go" (follows quic-go pattern)
2. **Keep it under 150 lines.** Libraries trend shorter. The README is a landing page, not docs.
3. **"Pure Go" goes in the title**, not in a features section. One mention is enough.
4. **Zero dependencies can be a single bullet** in a features list, stated matter-of-factly.
5. **Do NOT include Go API examples in the README.** Link to godoc. This is the universal pattern.
6. **DO include a shell-level usage example** if the library has a simple "hello world" (e.g., `go run` a minimal .go file).
7. **Skip:** comparison tables, benchmarks (unless exceptional), roadmap, changelog, animated demos.
8. **Include:** godoc badge, what Tor spec versions are supported (like quic-go lists RFCs), one-line install (`go get`).
9. **Security matters:** Follow syncthing's pattern of having a clear security reporting callout.
10. **Social proof early:** If any projects use tor-go, list them prominently (quic-go pattern).
