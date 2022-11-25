import type { DigestType } from './DigestType';
import type { DnssecAlgorithm } from './DnssecAlgorithm';

export interface TrustAnchor {
  readonly keyTag: number;
  readonly algorithm: DnssecAlgorithm;
  readonly digestType: DigestType;
  readonly digest: Buffer;
}
