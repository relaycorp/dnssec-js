import type { DatePeriod } from './DatePeriod';
import type { TrustAnchor } from './TrustAnchor';

export interface VerificationOptions {
  readonly dateOrPeriod: Date | DatePeriod;
  readonly trustAnchors: readonly TrustAnchor[];
}
