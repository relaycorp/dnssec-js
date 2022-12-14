import { createHash } from 'node:crypto';

import { DigestType } from '../../DigestType.js';
import { DnssecAlgorithm } from '../../DnssecAlgorithm.js';

const HASH_BY_DNSSEC_ALGO: { readonly [algo in DnssecAlgorithm]: string | null } = {
  [DnssecAlgorithm.RSASHA1]: 'sha1',
  [DnssecAlgorithm.RSASHA256]: 'sha256',
  [DnssecAlgorithm.RSASHA512]: 'sha512',
  [DnssecAlgorithm.ECDSAP256SHA256]: 'sha256',
  [DnssecAlgorithm.ECDSAP384SHA384]: 'sha384',
  [DnssecAlgorithm.ED25519]: null,
  [DnssecAlgorithm.ED448]: null,
};

export function getNodejsSignatureHashAlgo(dnssecAlgorithm: DnssecAlgorithm): string | null {
  if (!(dnssecAlgorithm in HASH_BY_DNSSEC_ALGO)) {
    throw new Error(`Unsupported DNSSEC algorithm (${dnssecAlgorithm})`);
  }
  return HASH_BY_DNSSEC_ALGO[dnssecAlgorithm];
}

export function getNodejsHashAlgo(algorithm: DigestType): string {
  switch (algorithm) {
    case DigestType.SHA1: {
      return 'sha1';
    }
    case DigestType.SHA256: {
      return 'sha256';
    }
    case DigestType.SHA384: {
      return 'sha384';
    }
    default: {
      throw new Error(`Unsupported hashing algorithm ${algorithm as number}`);
    }
  }
}

export function generateDigest(plaintext: Buffer, digestAlgorithm: DigestType): Buffer {
  const hashName = getNodejsHashAlgo(digestAlgorithm);
  const hash = createHash(hashName);
  hash.update(plaintext);
  return hash.digest();
}
