
Task 08 — Exposure (KEV/EPSS; SNOW optional)
Scope

From actor’s CVEs, join KEV/EPSS; sort by risk.

If SNOW configured, enrich with asset counts (read-only).

Integrate --exposure into Orpheus flow.

Acceptance

argo run orpheus --actor FIN7 --exposure prints prioritized CVEs.

Works without SNOW and marks it “unavailable” if not set.
