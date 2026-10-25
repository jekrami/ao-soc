/** Document knowledge cited for a Tier-2 decision (M09) — never an autopilot input. */

export interface KnowledgeChunk {
  id: string;
  title: string;
  path: string;
  excerpt: string;
}

export interface KnowledgeCitation {
  offered: number;
  status?: 'ok' | 'degraded' | 'disabled' | string;
  provider?: string;
  error?: string;
  chunks?: KnowledgeChunk[];
  cited: {
    id: string;
    title?: string | null;
    path?: string | null;
  }[];
  /** Ids the model returned that were never offered. Dropped, and kept. */
  fabricated: string[];
}
