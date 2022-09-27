import { KeyObject } from 'node:crypto';

import { DnssecAlgorithm } from '../DnssecAlgorithm';

type DNSSECAlgorithmMapping = { readonly [key: string]: DnssecAlgorithm };

const DSA_ALGORITHMS_BY_HASH: DNSSECAlgorithmMapping = {
  sha1: DnssecAlgorithm.DSA,
};
const ECDSA_ALGORITHMS_BY_CURVE: DNSSECAlgorithmMapping = {
  prime256v1: DnssecAlgorithm.ECDSAP256SHA256,
  secp384r1: DnssecAlgorithm.ECDSAP384SHA384,
};
const RSA_ALGORITHMS_BY_HASH: DNSSECAlgorithmMapping = {
  sha1: DnssecAlgorithm.RSASHA1,
  sha256: DnssecAlgorithm.RSASHA256,
  sha512: DnssecAlgorithm.RSASHA512,
};

const HASH_BY_CURVE: { readonly [curve: string]: string } = {
  prime256v1: 'sha256',
  secp384r1: 'sha384',
};

export function getDNSSECAlgoFromKey(publicOrPrivateKey: KeyObject): DnssecAlgorithm {
  const keyType = publicOrPrivateKey.asymmetricKeyType!;
  const asymmetricKeyDetails = publicOrPrivateKey.asymmetricKeyDetails!;
  const hashAlgorithm = asymmetricKeyDetails.hashAlgorithm;

  let algorithm: DnssecAlgorithm | null = null;
  if (keyType.startsWith('rsa')) {
    algorithm = RSA_ALGORITHMS_BY_HASH[hashAlgorithm!];
  } else if (keyType === 'dsa') {
    algorithm = DSA_ALGORITHMS_BY_HASH[hashAlgorithm!];
  } else if (keyType === 'ec') {
    const namedCurve = asymmetricKeyDetails.namedCurve;
    algorithm = ECDSA_ALGORITHMS_BY_CURVE[namedCurve!];
  } else if (keyType === 'ed25519') {
    algorithm = DnssecAlgorithm.ED25519;
  } else if (keyType === 'ed448') {
    algorithm = DnssecAlgorithm.ED448;
  }

  if (!algorithm) {
    throw new Error(`Unsupported algorithm (${keyType}, ${hashAlgorithm})`);
  }
  return algorithm;
}

export function getNodejsHashAlgoFromKey(publicOrPrivateKey: KeyObject): string | null {
  const asymmetricKeyDetails = publicOrPrivateKey.asymmetricKeyDetails!;

  let hash: string | null;
  if (asymmetricKeyDetails.hashAlgorithm) {
    hash = asymmetricKeyDetails.hashAlgorithm;
  } else if (publicOrPrivateKey.asymmetricKeyType === 'ec') {
    hash = HASH_BY_CURVE[asymmetricKeyDetails.namedCurve!];
  } else if (['ed25519', 'ed448'].includes(publicOrPrivateKey.asymmetricKeyType!)) {
    hash = null;
  } else {
    throw new Error('Unsupported key');
  }

  return hash;
}
