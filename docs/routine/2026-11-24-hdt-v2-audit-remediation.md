# 2026-11-24 — HDT v2 audit remediation candidate
## Changes
- New isolated Core implementation, retaining v0.1 compatibility via original CLI.
- F1 commitment and root-derived header MAC; F2 random parameter API, minimum length policy and corrected entropy assumptions; F3 NFC; F4 backend RFC 8452 KAT and wheel dependency; F5 canonical bounded format and encrypted final counts; F6 one-use derived keys with zero nonce; F7 dual-PRF assumption documented; F8 preserved 64 KiB random keyfile without inflated strength; F9 static import boundary.
- Added regression and negative tests. No secrets from users or production keyfiles in repository.
## Testing
Tests supplied, not yet executed against the committed branch at commit creation. CI matrix inherited from main; results must be checked. Local primitive-only probes verified the AES-GCM-SIV RFC vector and the fixed Argon2id fixture, not the complete implementation.
## Next
Run CI across all platforms; add independent interoperable full-container KAT, fuzzing, malformed authenticated records and fault injection; verify dependency patch versions and locks; improve Windows ACLs/crash handling, desktop random generation UX, offline backup verification. Evaluate higher memory suite, padding and explicit migration separately. No release until independent review.
