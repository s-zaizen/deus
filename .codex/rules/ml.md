---
paths:
  - "ml/**/*.py"
---
# Python ML Service

- Format: `ruff format`
- Lint: `ruff check`
- Tests: run focused host tests when possible; run `docker compose exec -T ml pytest /ml/tests --quiet` for the full suite.
- Keep FastAPI route handlers thin. Training, analysis, embedding, taint, and feature logic belongs in services or domain modules.
- Preserve continuous learning: every Verify Submit trains from accumulated labels unless public mode intentionally disables learning writes.
