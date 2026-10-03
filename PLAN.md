# PLAN (owned by the lead)

Order (owner 2026-10-03): client first, it is what runs on the router; then its libraries; then the servers.

- Phase 0, council: inventory of the client code and two independent porting proposals, then cross-review. Lead merges here.
- Phase 1+: filled from the council result.

Acceptance for the router client: joins a NetBird network, talks to peers directly and through relay,
survives restart; then RSS and binary size are measured on the router against the Go baseline in AGENTS.md.
