import type { DatePeriod } from './DatePeriod.js';
import type { TrustAnchor } from './TrustAnchor.js';

export interface VerificationOptions {
  readonly dateOrPeriod: Date | DatePeriod;
  readonly trustAnchors: readonly TrustAnchor[];
}
