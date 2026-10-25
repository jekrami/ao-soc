/** Entity risk types. */

import type { EntityType } from './common';

export interface Entity {
  id: string;
  type: EntityType;
  name: string;
  risk_score: number;
  confidence: number;
  reason: string;
  last_seen: string;
}
