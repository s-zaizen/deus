# AGENTS.md

Instructions for Codex and other AI coding agents working in this repository.

## Project Summary

**makina** is a security scanner made of a Rust API, Python ML service, and SvelteKit UI. It continuously self-learns from human TP/FP labels submitted via the Verify tab. The GBDT model retrains on every Verify Submit.

## Key Invariants

- Continuous learning: the model trains from the first label onward; there are no threshold gates. `model_stage` is a maturity label, not a capability switch.
- Retrain trigger: `DELETE /api/verify/queue/:case_no` and `POST /api/knowledge` submissions must keep triggering `POST /train` on the ML service unless public mode explicitly blocks learning writes.
- Scan pipeline: semgrep, CodeBERT semantic analysis, the taint engine, and structural property-pattern checks run in parallel; results are merged and deduplicated by CWE.
- Rust orchestrates, Python owns ML: scanner logic lives in `ml/`; the Rust crate calls it over HTTP through `MlClient`. Do not move ML logic into Rust.
- SvelteKit SSR stays disabled. Keep `export const ssr = false` in `frontend/src/routes/+layout.ts`.

## Source Of Truth

- `CONTRIBUTING.md`: setup, branch workflow, commit convention, testing.
- `docs/ARCHITECTURE.md`: system design, API topology, data flow.
- `.codex/rules/`: path-scoped working rules for backend, ML, and frontend.
- `.codex/commands/`: Codex playbooks for vulnerability queue and verification workflows.
- `CLAUDE.md` and `.claude/`: Claude Code equivalents. Keep Codex and Claude instructions consistent when workflow rules change.

## Local Development

```bash
docker compose up -d
docker compose up -d --build frontend
docker compose up -d --build backend
docker compose up -d --build ml
docker compose logs -f
```

Services: frontend `:3000`, backend `:7373`, ML `:8080`.

## Validation

Run the narrowest useful check after edits:

```bash
.codex/checks/check-path.sh <changed-file> [more-files...]
```

Stack-specific commands:

```bash
cargo fmt
cargo clippy --quiet -- -D warnings
cargo test --quiet

ruff format ml/
ruff check ml/

cd frontend && npm run check --silent
cd frontend && npm test --silent
```

Before pushing, run or install the pre-push hook:

```bash
bash .codex/hooks/pre-push
git config core.hooksPath .codex/hooks
```

Python pytest normally runs inside the `ml` container because heavy ML dependencies live there:

```bash
docker compose exec -T ml pytest /ml/tests --quiet
```

## Branch And Commit Rules

- Never push directly to `main`. A push to `main` triggers the Cloud Run deploy workflow and ships production at `makina.sh`.
- Use a working branch and PR for all changes. `dev` is allowed as a working branch when the user explicitly asks for it.
- Follow Conventional Commits with a one-line message and no body:

```text
feat(backend): ...
fix(ml): ...
chore: ...
docs: ...
```

- If a change affects API routes, directory layout, toolchain, scopes, or workflows, update `docs/ARCHITECTURE.md` and `CONTRIBUTING.md` in the same commit.

## Backend Rules

- Rust code lives under `crates/**/*.rs`.
- Format with `cargo fmt`.
- Lint with `cargo clippy -- -D warnings`; zero warnings.
- Run `cargo test` for behavior changes.
- Keep Rust as orchestration and HTTP/data boundaries; ML logic remains in Python.

## ML Rules

- Python ML code lives under `ml/**/*.py`.
- Format with `ruff format`.
- Lint with `ruff check`.
- Keep route handlers thin; model training and analysis logic belongs in `ml/makina_ml/services/` or domain modules.
- Preserve continuous retraining semantics unless public mode is intentionally handling the write path.

## Frontend Rules

- Frontend code lives under `frontend/**/*.svelte` and `frontend/**/*.ts`.
- Use Svelte 5 Runes: `$state()`, `$derived()`, `$effect()`, `$props()`. Do not introduce Svelte 4 stores or `writable()`.
- For reactive sets, use `import { SvelteSet } from 'svelte/reactivity'`.
- For public environment variables, use `import { PUBLIC_API_URL } from '$env/static/public'`.
- Keep Monaco worker imports on Vite `?worker` syntax:
  `import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'`.
- `npm run check` must pass before committing frontend changes.
