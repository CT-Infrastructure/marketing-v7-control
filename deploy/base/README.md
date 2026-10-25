# Inert base examples

Read `../../policies/container/README.md` first. These `.in` files have unresolved facts and are intentionally rejected by offline preflight. They are not installed units and contain no real image digest, component UID, secret, address or site path.

The Quadlet subset is stateless and has no network or automatic installation target. Native volumes and mounted secret references belong in separately reviewed component configuration; never add arbitrary host paths or runtime flags. No generator, systemd reload, pull, build or start command is provided here. Obtain exact target versions and independent sandbox receipts before any separately authorized runtime work.

The corrected one-shot profile explicitly disables implicit writable tmpfs (`ReadOnlyTmpfs=false`), uses JSON exec-form health checks and `Restart=no`. The generator-only resolved source in `policies/container/fixtures/synthetic.container` uses fictitious data and must never be installed or pulled. The controller must regenerate and verify the observed service; preflight remains offline-only and grants no runtime authority.
