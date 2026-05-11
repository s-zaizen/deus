---
paths:
  - "frontend/**/*.svelte"
  - "frontend/**/*.ts"
---
# Svelte 5 / SvelteKit

- Use Svelte 5 Runes: `$state()`, `$derived()`, `$effect()`, `$props()`. Do not use Svelte 4 stores or `writable()`.
- Reactive Set: `import { SvelteSet } from 'svelte/reactivity'`.
- Env vars: `import { PUBLIC_API_URL } from '$env/static/public'`.
- SSR is disabled: `export const ssr = false` in `src/routes/+layout.ts`; do not enable it.
- Monaco worker: `import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'` using Vite `?worker` syntax.
- Check: `npm run check` must pass before committing.
