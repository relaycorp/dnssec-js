import { DatePeriod } from './DatePeriod';
import { TrustAnchor } from './TrustAnchor';

export interface VerificationOptions {
  readonly dateOrPeriod: Date | DatePeriod;
  readonly trustAnchors: readonly TrustAnchor[];
}
