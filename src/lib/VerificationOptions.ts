import type { IDatePeriod } from './dates.js';
import type { TrustAnchor } from './TrustAnchor.js';

export interface VerificationOptions {
  readonly dateOrPeriod: Date | IDatePeriod;
  readonly trustAnchors: readonly TrustAnchor[];
}
