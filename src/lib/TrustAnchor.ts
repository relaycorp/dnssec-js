import type { DigestType } from './DigestType.js';
import type { DnssecAlgorithm } from './DnssecAlgorithm.js';

export interface TrustAnchor {
  readonly keyTag: number;
  readonly algorithm: DnssecAlgorithm;
  readonly digestType: DigestType;
  readonly digest: Buffer;
}
