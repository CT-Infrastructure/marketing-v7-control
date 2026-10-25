# F15 offline site planning runbook

The example is a strict nonsecret planning contract, not runtime configuration or a deployment installer. Every production input is null. The decision register maps every input to an UNSET record and an owner-role blocker. No DNS, CIDR, provider identity, installed version or production host is inferred. A future production configuration needs its own reviewed schema and private input process.

From the repository root, in an authorized Python 3.10+ environment with only the standard library:

```text
python -B config/site/validate_site.py config/site/site.example.json docs/decisions/site/decision-register.json
python -B -m unittest discover -s config/site -p test_validate_site.py -v
python -B config/site/validate_site.py config/site/site.example.json docs/decisions/site/decision-register.json --require-production-ready
```

Expected validator codes: 0 means a structurally safe, incomplete planning package; 1 means malformed, unknown, changed or unsafe inputs; 2 means production readiness is blocked. The final command must return 2, never 0. Unit tests assert these codes using temporary synthetic files. They need no network, accounts, installations or production access. `-B` prevents bytecode writes. The validator only reads its two explicit paths and writes redacted diagnostics to stdout; it has no network, shell, deployment or host-management functionality.

The validator requires exact keys, types, engineering facts, safety flags, null production values, one unique decision per input, fixed owner roles and explicit unresolved blockers. It rejects duplicate JSON keys, NaN/Infinity, invalid encoding, oversized documents, fabricated evidence and approval values. It never prints input values. This is a constrained allowlist, not a general secret scanner: do not feed secrets to it. Exit 0 proves neither truth of site facts nor acceptance or production authority. It intentionally rejects resolved production values even if a caller claims approval.

All holds stay active: deployment, DNS change, publication, spending and provider effects; outbound remains HOLD, production authorization false, approval reference null. No mode releases them. The validator does not consume approvals or execute application workflows. Restore/replay remains in HOLD until current permissions, native effects and human approvals are reconciled in separately qualified workflows.

Root/controller handoff:

1. Validate packet bindings, lease/fence, prerequisite F01 acceptance and source ancestry using trusted controller records. This worker cannot inspect the ledger or Git metadata; the declared base is packet-provided, not independently proven.
2. Verify the output artifact SHA-256 manifest and that only the declared regular files differ under the two owned paths. Reject links, unexpected files and stale results.
3. Execute the offline commands above on the exact integrated candidate. Python execution in the author sandbox is prohibited; its tests are NOT_RUN. Record actual command codes, candidate revision, executor identity and artifact hashes. A manifest or author result is not an independent receipt.
4. Independent review must examine validation boundaries and the human register, including negative cases. Root owns acceptance and any test/review separation. Do not treat authored tests as independent verification.
5. Route each production blocker to the role in the register. Continue admissible mock work. No production gate can be closed by this task or these tests.

No Git command, installation, network request, agent, deployment or host change is part of this runbook. Historical scripts and the legacy router archive are not execution authority. Application/worker jobs use the approved container baseline when separately implemented; firmware, Proxmox host management and OS services retain native exceptions. Rootless support and exact database/cache compatibility require evidence, not assumptions. Native workers must be inventoried before relevant production qualification.

Rollback of this documentation-only candidate is a trusted integrator operation restoring the previous versions of these files. There is no deployed state to roll back. Preserve receipts and decision history. Root must reject expired/revoked lease results rather than treating a worker exit as acceptance.

## Canonical evidence hashes

`evidence-manifest.json` hashes UTF-8 without BOM and canonical LF bytes. The manifest excludes itself and covers exactly the eight named source artifacts. No whitespace trimming, JSON reserialization, encoding replacement or final-newline insertion is allowed. The original author checks and their NOT_RUN statuses are historical and are preserved; the hash-policy correction is not new runtime proof.

For an exported exact Git candidate with LF text, run `python -B config/site/verify_evidence.py`; each raw file SHA-256 must equal its manifest entry. Root must repeat this on the exact committed revision and record that separate receipt. For a Windows materialization that uniformly uses CRLF in a file, run `python -B config/site/verify_evidence.py --normalize-crlf`; this explicitly verifies after CRLF-to-LF conversion and does not claim the raw CRLF hash matches. Mixed LF/CRLF, lone CR, invalid UTF-8 and BOM reject. Content changes, even missing final newline, change the hash. This review repair normalizes the previously authored mixed materializations once to canonical LF; the verifier never rewrites input.

Run `python -B -m unittest discover -s config/site -p 'test_*.py' -v` to include hash-policy regressions alongside the original nine planning tests. Their execution results belong in separate reviewer/controller evidence, not retroactive edits to the original author's checks.

Verification checks the manifest and every artifact for regular-file containment before reading, including rejecting symlink/junction parent directories and escaped paths. Run only on the isolated stable candidate snapshot; this is not a concurrent hostile filesystem service. JSON parsing receives explicitly decoded UTF-8 text and never auto-detects UTF-16/UTF-32 bytes. Tests include real escaping symlinks; a Windows privilege limitation must be reported and those tests must run on Linux before acceptance.
