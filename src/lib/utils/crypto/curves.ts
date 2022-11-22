import { DnssecAlgorithm } from '../../DnssecAlgorithm';

export const ECDSA_CURVE_LENGTH = {
  [DnssecAlgorithm.ECDSAP256SHA256]: 64,
  [DnssecAlgorithm.ECDSAP384SHA384]: 96,
};
