# Inert base examples

Read `../../policies/container/README.md` first. These `.in` files have unresolved facts and are intentionally rejected by offline preflight. They are not installed units and contain no real image digest, component UID, secret, address or site path.

The Quadlet subset is stateless and has no network or automatic installation target. Native volumes and mounted secret references belong in separately reviewed component configuration; never add arbitrary host paths or runtime flags. No generator, systemd reload, pull, build or start command is provided here. Obtain exact target versions and independent sandbox receipts before any separately authorized runtime work.
