# Git Workflow Rules: container-images

Applies to: all branches and commits in this repo.
These rules add to or narrow the global git workflow in `~/.claude/CLAUDE.md`.
On any conflict, this file takes precedence within this repo.

## Branch naming

| Work type | Pattern | Example |
| --- | --- | --- |
| Phase feature work | `feat/a<phase>-<slug>` | `feat/a2-scanner-policy` |
| Bug fixes | `fix/<slug>` | `fix/catalog-digest-drift` |
| Chores (deps, CI) | `chore/<slug>` | `chore/update-cosign-action` |

The phase number must match the active phase from the project context in `CLAUDE.md`.

## Worktrees

Always create worktrees inside the project at `.worktrees/<branch-slug>`:

```
git worktree add .worktrees/a2-scanner-policy feat/a2-scanner-policy
```

Never create worktrees at global or user-config paths.

## Commit rules

- All commits must be GPG-signed: use `git commit -S` every time.
- Follow Conventional Commits. Use the phase or component as the scope:
  - `feat(a1): replace docker pull with crane digest-copy`
  - `fix(catalog): correct target field for dhi-python-3.13`
  - `chore(ci): pin cosign action to digest`
- Never bypass the `no-em-dash` pre-commit hook or any other hook with `--no-verify`.

## PR discipline

- Never push directly to `main`.
- Every change, including single-line catalog edits, goes through a PR.
- PR title must follow Conventional Commits format (same scope rules as commits).
- Squash or rebase to a clean commit history before merge; do not merge noisy draft commits.
