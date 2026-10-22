# ADR-0001: Record architecture decisions

Status: accepted
Date: 2026-10-21

## Context

Keystone is built one story at a time, and several choices (Cedar over a hand-written policy
language, a fixed interceptor order, hash-chained audit) shape everything after them. Without a
written reason, each one gets re-argued or silently reversed later.

## Decision

I record each decision that is costly to reverse as a short ADR in `docs/adr/`, numbered in order:
context, decision, consequences, and when to revisit. An accepted ADR is not edited to change
its meaning. A later ADR supersedes it and says so. The summary table is in `docs/PLAN.md`
section 3.12.

I also record two choices made before the first story:

- **Licence: MIT.** The repository owner chose MIT. `LICENSE` holds the text and
  `pyproject.toml` declares it. Earlier planning notes assumed a different licence, and this
  decision replaces them.
- **Branches.** `main` holds only releases that passed a phase gate. `dev` is the integration
  branch. Story branches merge into `dev` with `--no-ff`, so one `git revert -m 1` undoes a story.

## Consequences

- Reviewers can read why, not only what. Each ADR is under one page.
- Writing an ADR is part of the story that makes the decision. It costs a few minutes.
- The pins in ADR-0002 and the licence above are not up for debate inside a story. Changing
  either needs a new ADR.

## Revisit when

Never for the practice itself. Individual ADRs name their own triggers.
