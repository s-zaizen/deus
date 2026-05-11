import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

function monacoChunk(id: string) {
	if (!id.includes('node_modules/monaco-editor/esm/vs/')) return;
	if (id.includes('/basic-languages/')) return 'monaco-languages';
	if (id.includes('/base/')) return 'monaco-base';
	if (id.includes('/platform/')) return 'monaco-platform';
	if (id.includes('/language/')) return 'monaco-language';
}

export default defineConfig(({ isSsrBuild }) => ({
	plugins: [sveltekit()],
	build: {
		chunkSizeWarningLimit: 1400,
		rollupOptions: {
			output: isSsrBuild ? undefined : { manualChunks: monacoChunk }
		}
	},
	optimizeDeps: {
		include: ['monaco-editor/esm/vs/editor/editor.api']
	}
}));
