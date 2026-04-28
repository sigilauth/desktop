# Violations Log — Linux Desktop

Append-only log of quality violations found during implementation and review.

Format: `| date | file | line | violation # | description | status |`

| Date | File | Line | Violation # | Description | Status |
|------|------|------|-------------|-------------|--------|
| 2026-04-26 | N/A | N/A | N/A | Initial implementation — no violations | GREEN |
| 2026-04-26 | envelope.rs | 131-180, 215-264 | P7 (HIGH) | Missing nonce tracking in envelope verification — replay attack possible within 300s window (Raven SIG-2026-RAVEN-P7) | FIXED (commit 1424687) |
