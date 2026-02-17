# Plan: Fix cmd/tor-client 404

> **Instructions for implementing agents:**
> - Work through slices in order
> - Use `/build [slice description]` to implement each slice — this includes code review and security assessment per slice
> - After EACH slice: check it off (`- [x]`) in this file and run `~/.claude/md2pdf.sh` on this file to update the PDF
> - If a slice is larger than expected, split it further before building
> - If you discover new slices needed, add them with checkboxes and regenerate the PDF

**Scope:** Feature

## Problem

The README links to `cmd/tor-client` but that path is 404 on GitHub. The files (`main.go`, `e2e_test.go`) exist locally but were never committed because `.gitignore` contains a bare `tor-client` pattern that matches both the compiled binary AND the `cmd/tor-client/` source directory.

## Slices

- [x] **F-1: Fix .gitignore and commit cmd/tor-client**
  - **What:** Change the `.gitignore` pattern from `tor-client` to `/tor-client` so it only ignores the compiled binary at the repo root, not the `cmd/tor-client/` source directory. Then add and commit the existing `cmd/tor-client/main.go` and `cmd/tor-client/e2e_test.go`.
  - **Files/areas:** `.gitignore`, `cmd/tor-client/main.go`, `cmd/tor-client/e2e_test.go`
  - **Acceptance criteria:**
    - `.gitignore` uses `/tor-client` instead of `tor-client`
    - `cmd/tor-client/main.go` is tracked by git
    - `cmd/tor-client/e2e_test.go` is tracked by git
    - `go build ./cmd/tor-client` still works
    - The compiled binary at repo root is still ignored
  - **Dependencies:** None
  - **Risks:** None. The files already exist and work — this is just a git tracking fix.

## Not Doing

- **Rewriting cmd/tor-client** — the existing code works, we just need to commit it
- **Updating README** — the link is already correct, the target was just missing from git
