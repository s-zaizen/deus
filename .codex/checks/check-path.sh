#!/usr/bin/env bash
# Run the narrowest repository checks implied by the changed paths.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: .codex/checks/check-path.sh <path> [more-paths...]" >&2
    exit 64
fi

root=$(git rev-parse --show-toplevel)
cd "$root"

need_rust=0
need_python=0
need_frontend=0
python_files=()

for file in "$@"; do
    case "$file" in
        *.rs)
            need_rust=1
            ;;
        *.py)
            need_python=1
            python_files+=("$file")
            ;;
        frontend/*.ts|frontend/*.svelte|frontend/src/*.ts|frontend/src/*.svelte|frontend/**/*.ts|frontend/**/*.svelte)
            need_frontend=1
            ;;
    esac
done

if [ "$need_rust" -eq 1 ]; then
    echo "codex check: cargo clippy" >&2
    cargo clippy --quiet -- -D warnings
fi

if [ "$need_python" -eq 1 ]; then
    echo "codex check: ruff check" >&2
    ruff check "${python_files[@]}"
fi

if [ "$need_frontend" -eq 1 ]; then
    echo "codex check: npm run check" >&2
    (cd frontend && npm run check --silent)
fi
