import type { Severity } from '$lib/types';

export interface SeverityTone {
	badge: string;
	border: string;
	panel: string;
	track: string;
	text: string;
	ruler: string;
	highlight: string;
	glyph: string;
}

export const severityPalette: Record<Severity, SeverityTone> = {
	critical: {
		badge: 'border-red-800/70 bg-red-950/50 text-red-300',
		border: 'border-l-red-600/90',
		panel: 'bg-red-950/15',
		track: 'bg-red-500',
		text: 'text-red-400',
		ruler: '#dc2626',
		highlight: 'rgba(239,68,68,0.12)',
		glyph: '#dc2626'
	},
	high: {
		badge: 'border-orange-800/70 bg-orange-950/45 text-orange-300',
		border: 'border-l-orange-600/90',
		panel: 'bg-orange-950/15',
		track: 'bg-orange-500',
		text: 'text-orange-400',
		ruler: '#ea580c',
		highlight: 'rgba(249,115,22,0.10)',
		glyph: '#ea580c'
	},
	medium: {
		badge: 'border-amber-800/70 bg-amber-950/45 text-amber-300',
		border: 'border-l-amber-600/90',
		panel: 'bg-amber-950/15',
		track: 'bg-amber-500',
		text: 'text-amber-400',
		ruler: '#ca8a04',
		highlight: 'rgba(234,179,8,0.10)',
		glyph: '#ca8a04'
	},
	low: {
		badge: 'border-sky-800/70 bg-sky-950/45 text-sky-300',
		border: 'border-l-sky-600/90',
		panel: 'bg-sky-950/15',
		track: 'bg-sky-500',
		text: 'text-sky-400',
		ruler: '#2563eb',
		highlight: 'rgba(96,165,250,0.10)',
		glyph: '#2563eb'
	}
};

export const defaultSeverityTone: SeverityTone = {
	badge: 'border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] text-gray-400',
	border: 'border-l-gray-700',
	panel: 'bg-[var(--mk-bg-panel)]',
	track: 'bg-gray-600',
	text: 'text-gray-400',
	ruler: '#64748b',
	highlight: 'transparent',
	glyph: '#64748b'
};

export function severityTone(severity: Severity | null | undefined): SeverityTone {
	return severity ? (severityPalette[severity] ?? defaultSeverityTone) : defaultSeverityTone;
}
