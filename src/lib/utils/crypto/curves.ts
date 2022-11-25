import { DnssecAlgorithm } from '../../DnssecAlgorithm.js';

export const ECDSA_CURVE_LENGTH = {
  [DnssecAlgorithm.ECDSAP256SHA256]: 64,
  [DnssecAlgorithm.ECDSAP384SHA384]: 96,
};

export const EDDSA_SERIALISED_KEY_LENGTH = {
  [DnssecAlgorithm.ED25519]: 32,
  [DnssecAlgorithm.ED448]: 57,
};
