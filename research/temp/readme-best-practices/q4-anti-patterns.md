# Q4: README Anti-Patterns to Avoid for a Security-Sensitive Go Library

Research date: 2026-02-17

## Methodology

Examined README files from 15+ security-sensitive Go projects (bine, age, CIRCL, memguard, obfs4, wireguard-go, Vault, go-libp2p, Pond, yggdrasil-go, CertMagic, and others). Cross-referenced with research on developer trust signals, Filippo Valsorda's guidance on crypto library design, and the Go standard library's own security audit approach.

---

## Anti-Pattern 1: The Wall-of-Disclaimers

### What it looks like
```
WARNING: This software is experimental. Do NOT use in production.
Use at your own risk. No warranty is provided. This has not been
audited. The authors are not responsible for any damages. This
may contain critical vulnerabilities. DO NOT rely on this for
security-critical applications.
```

### Why it's toxic

Research on disclaimers shows that excessive disclaimers erode trust rather than build it. Users who encounter blanket "use at your own risk" language feel the maintainer is either covering for known problems or doesn't believe in their own work. Courts, regulators, and users all expect some level of accountability -- a total denial of it signals untrustworthiness.

The **disclaimer paradox**: disclaimers that try to cover everything end up covering nothing. They become noise that developers scroll past, defeating the purpose entirely.

### What good projects do instead

**Cloudflare CIRCL** (crypto library) has a single, specific disclaimer:

> "This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application since part of its content is experimental."

This works because it:
- Is one paragraph, not a wall
- Explains *why* caution is needed (experimental content, API changes)
- Says "take caution" not "DO NOT USE"
- Pairs the warning with a security reporting policy

**bine** (Go Tor library) has zero disclaimers. It simply presents what it does. No apologies.

**age** (encryption tool by Filippo Valsorda) has zero disclaimers. It lets its spec, design transparency, and author reputation do the talking.

**obfs4** (Tor pluggable transport) has zero disclaimers despite being cryptographic software.

### The rule for tor-go

**One sentence maximum.** If a disclaimer is needed, it should be specific about what's experimental and why, not a generic "use at your own risk." Better yet, communicate maturity through specificity about what IS implemented and tested, which implicitly communicates what isn't ready yet.

---

## Anti-Pattern 2: The Apology README

### What it looks like
```
This is just a hobby project. I'm not a security expert.
This probably has bugs. There are many things missing.
I haven't had time to implement X, Y, Z yet.
Please don't judge the code quality, it's a work in progress.
```

### Why it kills adoption

Self-deprecation destroys confidence instantly. If the author doesn't believe in the project, why should anyone else? Security-sensitive projects live or die on perceived competence.

### Evidence from real projects

Not a single one of the 15+ projects examined includes self-deprecating language. Even **Pond**, which is literally abandoned and the author recommends not using it, states the situation factually ("Pond is in stasis") without apologizing for it.

**yggdrasil-go** calls itself "an early-stage implementation" -- factual, not apologetic. It doesn't say "sorry, this isn't ready." It says what stage it's at and lets the user decide.

**wireguard-go** recommends using the kernel module on Linux instead of itself. It states this as a fact ("you should instead use the kernel module, which is faster and better integrated"), not as an apology.

### The rule for tor-go

State facts. "This library implements X. It does not yet implement Y." Never apologize for the project's existence or current state. Confidence in presentation does not mean dishonesty -- it means respecting the user's ability to evaluate facts.

---

## Anti-Pattern 3: The Feature Wishlist README

### What it looks like
```
## Roadmap
- [ ] IPv6 support
- [ ] Hidden service hosting
- [ ] Descriptor verification
- [ ] Bridge support
- [ ] Pluggable transports
- [ ] Performance optimization
- [ ] Full spec compliance
```

### Why it backfires for security projects

A long TODO list in the README communicates incompleteness, not ambition. For a security-sensitive project, every unchecked box is a reason to not adopt. Developers reading this think: "So half of this doesn't work yet."

### Evidence from real projects

Q1 research confirmed: zero of the 9 top Go projects surveyed include a roadmap in their README. Not age, not wireguard-go, not quic-go, not any of them. Roadmaps live in GitHub Issues, project boards, or separate documents -- never in the README.

### The rule for tor-go

Remove any roadmap or TODO list from the README. Instead, state what IS implemented. Known limitations (like no IPv6) can be mentioned in a "Limitations" or "Scope" section as factual statements, but never as a checklist of unfinished work. The README markets what exists, not what's missing.

---

## Anti-Pattern 4: Overstating Security Properties

### What it looks like
```
Secure, private, anonymous Tor connections in Go.
Military-grade encryption. Fully anonymous browsing.
```

### Why it's dangerous

Overclaiming security properties is the fastest way to lose credibility with security researchers and experienced developers. If a vulnerability is later found, every overclaim becomes evidence of incompetence or dishonesty.

Filippo Valsorda's approach to Go's crypto libraries focuses on "managing complexity through API design, documentation, and providing guidance so users can use libraries safely and correctly" -- not on making bold security claims. The Go team's crypto audit by Trail of Bits is presented factually: here's what was audited, here's what was found. No chest-beating.

### What good projects do instead

- **age**: Describes itself as "a simple, modern and secure file encryption tool" -- the word "secure" appears once, in context, without superlatives
- **wireguard-go**: "Go Implementation of WireGuard" -- security is implied by the protocol, not claimed by the implementation
- **CIRCL**: Lists what algorithms are implemented, not how secure they are
- **bine**: "Pure Go API for Tor" -- no security claims at all

### The rule for tor-go

Describe what the library does (connects to the Tor network, creates circuits, routes traffic). Let the Tor protocol's security properties speak for themselves. Never claim the *implementation* is secure, private, or anonymous -- those properties belong to the Tor spec, and the implementation's correctness in delivering them is an ongoing verification.

---

## Anti-Pattern 5: Exhaustive API Documentation in the README

### What it looks like
```
## API Reference

### func NewClient(options ...Option) (*Client, error)
Creates a new Tor client with the given options...

### func (c *Client) Connect(address string) (net.Conn, error)
Establishes a connection through the Tor network...

[continues for 200+ lines]
```

### Why it's wrong for Go libraries

Q1 research established this definitively: **none of the 9 top Go libraries include API examples in the README.** All defer to godoc / pkg.go.dev. The README is a landing page, not documentation.

For security-sensitive libraries specifically, inline API docs in the README become a maintenance liability. When the API changes but the README doesn't update, you have stale security-relevant documentation. godoc stays in sync with the code automatically.

### The rule for tor-go

Zero Go API code in the README. Link to pkg.go.dev. At most, a shell-level `go get` command and a link to an example directory.

---

## Anti-Pattern 6: Badge Overload and Vanity Badges

### What it looks like
```
![License](badge) ![Downloads](badge) ![Contributors](badge)
![Stars](badge) ![Last Commit](badge) ![Code Size](badge)
![Awesome Go](badge) ![Made with Go](badge) ![Twitter](badge)
```

### Evidence

Q2 research found:
- **Zero** top Go projects use a license badge
- The sweet spot is 3 badges (Go Reference, CI, Go Report Card)
- Projects with 7-8 badges look cluttered
- Download count, "awesome" list, and social badges are not Go conventions
- A code coverage badge with a low number actively hurts credibility

For a security-sensitive project, a badge wall signals "this project cares about appearances over substance." Security researchers are especially likely to view this negatively.

### The rule for tor-go

Maximum 3 badges. Go Reference is near-mandatory. CI status and Go Report Card are the standard second and third choices. Nothing else unless there's a specific reason (e.g., a security audit badge if one has been completed).

---

## Anti-Pattern 7: The "Not Affiliated" Over-Disclaimer

### What it looks like
```
DISCLAIMER: This project is NOT affiliated with, endorsed by, or
associated with The Tor Project, Inc. Use of the Tor name does not
imply endorsement. This is an independent implementation and The Tor
Project bears no responsibility for this software.
```

### Why it's a problem

While factual accuracy matters, a prominent legal-style disclaimer at the top of the README makes the project look like it's expecting a lawsuit. It creates an adversarial tone before the reader even learns what the project does.

### What good projects do instead

- **bine** (Go Tor library): No affiliation disclaimer at all, despite using "Tor" extensively
- **obfs4** (Tor pluggable transport): No affiliation disclaimer
- **go-ethereum**: No Ethereum Foundation disclaimer
- **yggdrasil-go**: No protocol affiliation disclaimer

None of these projects disclaim their relationship with the parent protocol/network. If needed at all, a brief note at the bottom (not the top) in a neutral tone is sufficient.

### The rule for tor-go

If any affiliation note is needed, place it at the bottom in one sentence, stated neutrally: "This is an independent implementation of the Tor protocol." Not at the top, not in bold, not in legal language.

---

## Anti-Pattern 8: Burying the Lead with Context

### What it looks like
```
## Background

The Tor network was created in the mid-2000s by the US Naval Research
Laboratory. It uses onion routing, a technique first described in a
1996 paper by Goldschlag, Reed, and Syverson. The Tor protocol has
gone through several versions...

[500 words of history before the reader learns what this library does]
```

### Why it fails

Developers evaluating a library want to know three things immediately: what is it, how do I use it, and should I trust it. Background information on the Tor protocol assumes the reader doesn't already know what Tor is -- but anyone searching for a Go Tor client library already knows.

### Evidence

Every top Go project opens with what the project IS, not its history:
- quic-go: "A QUIC implementation in pure Go"
- age: "a simple, modern and secure file encryption tool, format, and Go library"
- wireguard-go: "Go Implementation of WireGuard"

Zero words of protocol history in any of them.

### The rule for tor-go

First line states what it is. No Tor history, no onion routing explainer. Link to the Tor spec for anyone who wants background.

---

## Anti-Pattern 9: Comparison Tables with Alternatives

### What it looks like
```
## Comparison

| Feature | tor-go | bine | Arti | tor daemon |
|---------|--------|------|------|------------|
| Pure Go | Yes | No* | No | No |
| ...     | ...    | ...  | ...  | ...        |
```

### Why it's risky for security projects

Q1 research confirmed: zero of the 9 top Go projects include comparison tables. For a security-sensitive project, the risks multiply:

1. Any inaccuracy in comparing another project's security properties is a credibility destroyer
2. It invites adversarial scrutiny from maintainers of compared projects
3. It dates rapidly as other projects evolve
4. It positions you as a competitor rather than a tool -- developers want tools, not competitors

### The rule for tor-go

No comparison tables. If the project's differentiators matter (pure Go, no CGo, no daemon dependency), state them as facts about tor-go, not as comparisons with others.

---

## Anti-Pattern 10: The "Security Considerations" Essay

### What it looks like
```
## Security Considerations

This library implements the Tor protocol, which provides anonymity through
onion routing. However, anonymity is a complex property that depends on
many factors beyond the protocol implementation. Users should be aware that:

- Traffic analysis may still be possible
- Exit node operators can see unencrypted traffic
- Browser fingerprinting is not addressed by this library
- DNS leaks may occur if not properly configured
- [continues for several paragraphs about Tor's general threat model]
```

### Why it's counterproductive

This conflates the library's responsibilities with the Tor protocol's properties. A Go library doesn't need to re-explain Tor's threat model -- that's documented extensively by The Tor Project. Including it in the README:

1. Makes the README too long (libraries should be under 150 lines per Q1 findings)
2. Creates stale documentation if Tor's threat model evolves
3. Implies the library author is responsible for Tor's overall security properties
4. Overwhelms the reader before they've even decided whether to use the library

### What to do instead

A brief scope statement is sufficient: "This library implements the Tor v3 client protocol. It does not provide a full Tor Browser experience. For Tor's security properties and threat model, see [link to Tor Project docs]."

---

## Summary: The Trust Equation for Security-Sensitive Go Libraries

Based on examining 15+ real projects, trust in a security-sensitive Go library README comes from:

### What builds trust
1. **Specificity over vagueness** -- "Implements Tor v3 onion services using ntor handshakes" beats "Secure Tor connections"
2. **Factual tone** -- State what is implemented, what isn't, what the scope is
3. **Brevity** -- Short READMEs signal confidence; long READMEs signal insecurity
4. **Deferring to authoritative sources** -- Link to godoc, link to Tor spec, link to security policy
5. **Security reporting channel** -- Every credible security project has one (Vault, syncthing, CIRCL all feature this prominently)
6. **Showing, not telling** -- CertMagic says it powers "trillions of connections" rather than "this is production-ready"

### What destroys trust
1. **Multiple disclaimers** -- One is enough; more signals fear
2. **Self-deprecation** -- If you don't believe in it, nobody will
3. **Overclaiming** -- "Military-grade" / "fully anonymous" / "secure" as headline adjectives
4. **Walls of text** -- Security researchers evaluate quickly; long READMEs get closed
5. **TODO lists in the README** -- Communicate what works, not what's broken
6. **Stale information** -- An outdated README is worse than a minimal one

### The golden formula observed across top projects

```
Confidence = Specificity + Brevity + Factual Tone - (Disclaimers + Vagueness + Self-Deprecation)
```

The best security-sensitive Go libraries (age, wireguard-go, bine) say less, not more. They state facts, link to authoritative sources, and let the code speak through godoc. They don't apologize, they don't overclaim, and they don't over-explain. The README's job is to get out of the way and let the developer evaluate the code.

---

## Specific Application to tor-go

Given tor-go's current state (working Tor v3 client, some limitations like no IPv6, no service hosting, descriptor verification TODO):

### Do
- State what it implements: "Pure Go Tor v3 client library. Creates circuits, establishes streams, routes TCP traffic through the Tor network."
- Mention limitations as scope boundaries, not apologies: "Client connections only. Does not host onion services."
- Include a SECURITY.md or security reporting email
- Keep the README under 100 lines

### Do not
- Add "experimental" / "not production ready" / "use at your own risk" at the top
- List every TODO or missing feature
- Explain what Tor is or how onion routing works
- Claim the library is "secure" or "anonymous"
- Compare with bine, Arti, or the Tor daemon
- Include Go API code examples (use godoc)
- Add more than 3 badges
- Apologize for limitations
