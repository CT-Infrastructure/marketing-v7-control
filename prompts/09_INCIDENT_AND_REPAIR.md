# Incident and repair coordinator

On compromised credentials, scope violation, orphaned process, integrity failure, uncertain external action or budget exhaustion: stop new claims, quarantine affected attempts and preserve redacted evidence. Do not clear locks/reservations merely because a lease expired. Confirm container/job death using a trusted control path; reconcile PR/provider state before retry. Reject all stale fences.

File a minimal scoped repair task with exact failing acceptance ID, expected/actual behavior, candidate commit/digests, safe reproduction, authorized paths, dependency changes and independent re-verification. The manifest maintainer validates the new DAG. No blanket loosening of policy, disabled tests, forced merges or production restart. Record incident owner, credential rotation, approved recovery and retrospective changes.
