# F11 subprocess restart candidate

Run only under the trusted root executor's Linux bwrap isolation. No test reaches a real controller ledger. The original 51 test_local.py tests are retained; additive sidecar regressions require bounded owned children.

Provide an existing dedicated local durable directory through F11_PROCESS_TEST_ROOT. Mount it read/write into the sandbox; source should remain read-only. The fixture rejects links, UNC paths and filesystem types other than ext4, xfs and btrfs using the longest matching /proc/self/mountinfo mount. The executor must independently attest that the backing device is dedicated local durable storage: filesystem type cannot establish physical durability or exclude shared block storage. Overlay/tmpfs/NFS/CIFS and unknown types fail closed. Do not install missing dependencies.

Example inside the approved sandbox, from the exported source root:

    PYTHONDONTWRITEBYTECODE=1 F11_PROCESS_TEST_ROOT=/approved/f11-scratch F11_PROCESS_EXPECTED_REVISION="$TRUSTED_COMMITTED_REVISION" F11_PROCESS_SOURCE_MANIFEST=/approved/executor/f11-source-manifest.json python3 -B -m unittest discover -s tests/controller -p 'test_*.py' -v

The trusted executor must set TRUSTED_COMMITTED_REVISION to the canonical nonzero lowercase 40-hex Git commit and supply F11_PROCESS_SOURCE_MANIFEST as an absolute executor path visible inside the sandbox. Obtain that revision and all six raw-byte SHA-256 values from the same frozen committed tree. Mount those source bytes read-only. The JSON must contain exactly these two keys, and source_hashes must cover exactly these six paths (replace placeholders with actual lowercase hex values):

```json
{
  "source_revision": "<same nonzero lowercase 40-hex committed revision>",
  "source_hashes": {
    "tests/controller/test_process_restart.py": "<64-hex SHA-256>",
    "tests/controller/test_process_revision.py": "<64-hex SHA-256>",
    "tests/controller/test_local.py": "<64-hex SHA-256>",
    "orchestration/controller/local.py": "<64-hex SHA-256>",
    "tools/scheduler.py": "<64-hex SHA-256>",
    "docs/orchestration/capacity/check_dispatch_inputs.py": "<64-hex SHA-256>"
  }
}
```

Export mode verifies the supplied declaration and bytes; it does not independently authenticate Git history or establish runtime qualification. A file SHA-256 is not a Git commit. This unpublished candidate must first be committed, then rerun against its actual new HEAD with a regenerated manifest. Do not attach an ancestor revision to new candidate bytes. Checkout mode independently compares covered bytes to its current HEAD; the six-path binding does not assert whole-tree cleanliness.

For process semantics only, set F11_PROCESS_TEMP_ROOT to a supplied scratch directory instead. Never set both variables. This mode records durability NOT_RUN, including when the directory happens to be on disk. Without either variable the added test skips, explicitly noting durability NOT_RUN. No durability qualification is inferred from the old temporary fixtures.

Each run creates a unique f11-process-* directory, retained for review. Eight cases cross clean/abrupt child exit with independently limiting path, explicit lock, capacity and cost reservations. The writer commits its synthetic fixture, records sanitized state and exits normally or via os._exit(23). The parent waits/reaps it before launching a separate verifier against the same database. The verifier checks current identity and reservation equality, conflicting admission, stale fence completion, and expiry quarantine with retained reservations. Expiry uses an injected synthetic clock rather than sleep. Child waits are bounded; timeout handling kills/reaps only the exact Popen child. This is process restart evidence, not power-loss evidence.

process-evidence.json records source-byte hashes, source revision, actual child PIDs and exit codes, reservation comparisons and evidence limits. before.json and verified.json contain sanitized data only. Synthetic SQLite fixtures contain generated synthetic bearer values; they are not evidence for publication and must stay in approved scratch. No bearer is printed or emitted in JSON. Parent suppresses child output to prevent exception details leaking fixture bearer values. A failed child has its exit code recorded and fails the test; independent root diagnosis may inspect only these synthetic fixture artifacts.

Authoring-stage runtime cases: 0. Root must execute all 51 existing tests plus this suite, scan evidence and independently review the candidate. G02/F12, provider, production, power-loss and multi-host qualification remain NOT_RUN. The output result omits lease fields because this scoped packet supplies no lease identity and explicitly forbids emitting lease strings; it follows the task-specific result contract instead of inventing authority to satisfy the generic schema.