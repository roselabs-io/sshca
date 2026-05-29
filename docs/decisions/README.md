# Decisions (ADRs)

Architecture Decision Records for `sshca`. One file per decision, numbered, chronological. Same conventions as the upstream `gateway` repo.

## Conventions

**Filename:** `ADR-NNN-short-kebab-case-description.md` (3-digit zero-padded, monotonic).

**ADR numbering is local to this repo.** `sshca` starts its own ADR-001 from scratch. ADRs in the upstream `gateway` repo that informed sshca's existence are pointed to from [inherited.md](inherited.md), not duplicated or renumbered here.

**Status terms** (same vocabulary as upstream):

| Status | Meaning |
|---|---|
| `Proposed` | Decision drafted, not yet committed |
| `Accepted` | Decision agreed to but not yet implemented |
| `Accepted — Implemented YYYY-MM-DD` | Decision live in the code |
| `Revised` | Original decision modified; ADR still documents the journey |
| `Superseded by ADR-NNN` | Replaced by a later ADR. Don't delete; link |

**Structure:**

```markdown
# ADR-NNN: Title

**Status:** ...

<1-3 paragraph synthesis>

**Decision:** <crisp callout if needed>

**Why:** <reasoning, alternatives>

**Constraint discovered** (optional): <gotchas from deploy>

**References:** <cross-links to code, upstream ADRs, related docs>
```

## What goes in an ADR vs not

- **Yes:** non-obvious architectural choices, scope changes, alternatives evaluated, constraints discovered during deploy.
- **No:** day-to-day implementation choices, code style, things obvious from the code.

Rule of thumb: if a future reader would otherwise re-derive the decision (or worse, re-make a mistake the ADR captures), write the ADR.

## Index

| # | Title | Status |
|---|---|---|
| _none yet_ | — | — |

First sshca-series ADR lands when sshca makes its first non-inherited decision (likely a flag rename or output-format polish discovered during the code migration from upstream).

## Inherited from upstream

See [inherited.md](inherited.md) for ADRs in the `gateway` repo that informed sshca's existence and shape. They are not renumbered into this repo's ADR series.
