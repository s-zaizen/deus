# Codex Workspace Notes

This directory mirrors the Claude Code repo guidance in a Codex-friendly shape.

## Contents

- `rules/`: path-scoped implementation rules for Rust backend, Python ML, and SvelteKit frontend work.
- `commands/`: reusable Codex playbooks for vulnerability queue and verification workflows.
- `checks/check-path.sh`: narrow post-edit checker for changed files.
- `hooks/pre-push`: full pre-push validation suite.

## Hook Setup

Codex does not install repository hooks automatically. To use the Codex pre-push hook for manual pushes:

```bash
git config core.hooksPath .codex/hooks
```

The Claude Code hook bundle remains in `.claude/hooks`. Only one `core.hooksPath` can be active in a clone, so choose the bundle that matches the tool you are using.

## Keeping In Sync

When assistant workflow rules change, update all relevant files together:

- `AGENTS.md`
- `.codex/`
- `CLAUDE.md`
- `.claude/`
- `CONTRIBUTING.md`
- `docs/ARCHITECTURE.md`
