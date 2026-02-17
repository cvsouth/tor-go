# Q2: Badges and Visual Elements for Go Libraries

## Research Method

Fetched raw README.md files from 13 popular Go projects on GitHub and catalogued every badge, logo, and visual element in each.

## Projects Surveyed

| Project | Stars (approx) | Badge Count | Has Logo/Banner |
|---------|----------------|-------------|-----------------|
| age (filippo.io) | 18k | 3 | Yes (SVG, light/dark) |
| mkcert | 51k | 0 | No |
| Caddy | 61k | 7 | Yes (logo + sponsor logos) |
| Hugo | 78k | 3 | Yes (wide SVG) |
| Cobra | 39k | 4 | Yes (logo) |
| Gin | 80k | 8 | Yes (small, right-aligned) |
| Chi | 19k | 1 | Yes (small SVG) |
| Bubble Tea | 29k | 3 | Yes (light/dark) |
| gorilla/mux | 21k | 4 | Yes (logo) |
| testify | 24k | 3 | No |
| zap | 22k | 3 | Yes (logo) |
| bine (Tor library) | 0.5k | 1 | Yes (small logo) |
| quic-go | 10k | 4 | Yes (wide logo) |
| go-plugin | 5k | 0 | No |

## Badge Frequency Analysis

Counting how often each badge type appears across all 13 projects:

| Badge Type | Count | Projects Using |
|------------|-------|----------------|
| **Go Reference / GoDoc** | 11 | age, caddy, hugo, cobra, gin, chi, bubbletea, mux, testify, zap, bine |
| **CI / Build Status** | 9 | caddy, hugo, cobra, gin, bubbletea, mux, testify, zap, quic-go |
| **Go Report Card** | 5 | hugo, cobra, gin, testify |
| **Code Coverage** | 4 | gin, mux, zap, quic-go |
| **Sourcegraph** | 2 | caddy, gin |
| **Release version** | 2 | gin, bubbletea |
| **License** | 0 | none (!) |
| **Social (Twitter/Slack)** | 2 | caddy, cobra |
| **Custom/Project-specific** | 4 | age (man page, spec), caddy (best practices, cloudsmith), quic-go (fuzzing, docs site) |

### Key Observation: License Badge is Absent

Not a single top Go project uses a license badge. The license is conveyed via the LICENSE file and GitHub's automatic detection. This is a strong signal that license badges are noise in the Go ecosystem.

## The "Sweet Spot" for Badge Count

| Badge Count | Projects |
|-------------|----------|
| 0 | mkcert, go-plugin |
| 1 | chi, bine |
| 3 | age, hugo, bubbletea, testify, zap |
| 4 | cobra, mux, quic-go |
| 7-8 | caddy, gin |

**The clear sweet spot is 3-4 badges.** The majority of well-regarded Go libraries land here. Projects with 7-8 badges (Caddy, Gin) are large framework-scale projects where more badges are contextually appropriate but still look busy.

Projects with 0 badges (mkcert, go-plugin) prove that zero badges is also a viable choice -- the code speaks for itself. But for a library that needs to build trust with potential users, 3 badges is the most common pattern among successful Go projects.

## The "Core Three" Badge Set for Go Libraries

Based on frequency data, the three most valuable badges for a Go library are:

1. **Go Reference** (pkg.go.dev badge) -- appears in 11/13 projects. This is essentially mandatory. It signals "this is a real Go package with documentation."
2. **CI / Build Status** (GitHub Actions) -- appears in 9/13. Signals the project has automated testing and it passes.
3. **Go Report Card** -- appears in 5/13. Go-ecosystem-specific quality signal.

A fourth badge worth considering is **Code Coverage** if you have strong numbers (>80%). Otherwise it can work against you.

## Logo and Banner Patterns

**10 out of 13 projects use a logo or banner image.** This is a strong majority.

### Logo Styles Observed

| Style | Examples | Notes |
|-------|----------|-------|
| **Wide banner/wordmark** | Hugo, quic-go | Full-width, prominent branding |
| **Centered medium logo** | age, Cobra, zap, gorilla/mux | 200-600px, clean and focused |
| **Small accent logo** | Chi (220px), Gin (159px, right-aligned), bine (180px) | Understated, doesn't dominate |
| **Light/dark responsive** | age, Bubble Tea | Uses `<picture>` with `prefers-color-scheme` |

### Pattern: Libraries (not applications) tend toward smaller, understated logos

- Chi: 220px SVG
- bine: 180px logo
- Gin: 159px, right-aligned (doesn't take center stage)
- zap: centered but modest

Applications (Hugo, Caddy, quic-go) tend toward larger/wider branding.

### Light/Dark Mode Support

age and Bubble Tea both use the HTML `<picture>` element with `prefers-color-scheme` media queries. This is a polished touch that relatively few projects adopt, making it a differentiator without being gimmicky:

```html
<picture>
    <source media="(prefers-color-scheme: dark)" srcset="logo_white.svg">
    <source media="(prefers-color-scheme: light)" srcset="logo.svg">
    <img alt="description" width="600" src="logo.svg">
</picture>
```

## "No External Dependencies" -- How Projects Signal This

None of the surveyed projects use a badge for dependency count or "zero dependencies." Instead, this is communicated through:

1. **Prose in the description** -- chi says "no external dependencies" in its introduction text
2. **Feature lists** -- bullet point mentioning stdlib-only
3. **Go module file** -- sophisticated users check `go.mod` directly

There is no established convention for a "zero dependencies" badge in the Go ecosystem. A text mention is the standard approach.

## Badge Sources

| Source | Usage |
|--------|-------|
| **shields.io** | Most custom badges (version, social, custom labels) |
| **pkg.go.dev/badge** | Official Go Reference badge -- most common |
| **github.com/.../badge.svg** | GitHub Actions CI status |
| **goreportcard.com/badge** | Go Report Card |
| **codecov.io/.../badge.svg** | Code coverage |
| **godoc.org** | Legacy GoDoc (some older projects) |

**pkg.go.dev** is the canonical source for Go documentation badges. Some older projects still reference godoc.org but new projects should use pkg.go.dev.

## Recommendations for tor-go

### Badges (pick 3)

```markdown
[![Go Reference](https://pkg.go.dev/badge/github.com/cvsouth/tor-go.svg)](https://pkg.go.dev/github.com/cvsouth/tor-go)
[![Build Status](https://github.com/cvsouth/tor-go/actions/workflows/test.yml/badge.svg)](https://github.com/cvsouth/tor-go/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cvsouth/tor-go)](https://goreportcard.com/report/github.com/cvsouth/tor-go)
```

These three are the most commonly used across top Go libraries and each provides distinct value:
- Go Reference = "this has docs"
- Build Status = "this is tested"
- Go Report Card = "this is quality Go code"

### Logo

A small-to-medium logo (180-300px) is appropriate for a library (not an application). The bine project (the closest comparable -- a Go Tor library) uses a 180px logo, which feels right.

Light/dark mode support via `<picture>` is a polished touch borrowed from age (also by Filippo Valsorda, a respected Go/crypto developer). Worth doing if a logo is created.

### "No external dependencies"

State this in prose, not a badge. A bullet point in a features list or a line in the introduction is the established Go convention:

> "Pure Go implementation with zero external dependencies"

### What NOT to include

- License badge (no top Go project uses one)
- Download count badge (not a Go convention)
- Sourcegraph badge (niche, only 2/13 use it)
- Social media badges (unless the project has a significant community)
- "Awesome Go" badge (premature for a new project)
- Code coverage badge (only if numbers are strong, otherwise it's a liability)

## Summary

The minimal effective set for a Go library README is:

1. **Small/medium logo** (optional but 10/13 top projects have one)
2. **Three badges**: Go Reference, CI Status, Go Report Card
3. **Prose mention** of zero dependencies (not a badge)
4. **No license badge** -- not the Go convention

This matches the pattern used by the majority of successful Go libraries including cobra, hugo, testify, zap, and bubbletea.
