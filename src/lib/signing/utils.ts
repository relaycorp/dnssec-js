import { DnssecAlgorithm } from '../DnssecAlgorithm';

const HASH_BY_DNSSEC_ALGO: { readonly [algo in DnssecAlgorithm]: string | null } = {
  [DnssecAlgorithm.DSA]: 'sha1',
  [DnssecAlgorithm.RSASHA1]: 'sha1',
  [DnssecAlgorithm.RSASHA256]: 'sha256',
  [DnssecAlgorithm.RSASHA512]: 'sha512',
  [DnssecAlgorithm.ECDSAP256SHA256]: 'sha256',
  [DnssecAlgorithm.ECDSAP384SHA384]: 'sha384',
  [DnssecAlgorithm.ED25519]: null,
  [DnssecAlgorithm.ED448]: null,
};

export function getNodejsHashAlgorithmFromDnssecAlgo(
  dnssecAlgorithm: DnssecAlgorithm,
): string | null {
  const hash = HASH_BY_DNSSEC_ALGO[dnssecAlgorithm];
  if (hash === undefined) {
    throw new Error(`Unsupported DNSSEC algorithm (${dnssecAlgorithm})`);
  }
  return hash;
}
