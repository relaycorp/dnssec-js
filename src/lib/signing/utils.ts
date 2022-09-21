import { KeyObject } from 'node:crypto';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';
import { DigestType } from '../DigestType';

type DNSSECAlgorithmMapping = { readonly [key: string]: DNSSECAlgorithm };

const DSA_ALGORITHMS_BY_HASH: DNSSECAlgorithmMapping = {
  sha1: DNSSECAlgorithm.DSA,
};
const ECDSA_ALGORITHMS_BY_CURVE: DNSSECAlgorithmMapping = {
  prime256v1: DNSSECAlgorithm.ECDSAP256SHA256,
  secp384r1: DNSSECAlgorithm.ECDSAP384SHA384,
};
const RSA_ALGORITHMS_BY_HASH: DNSSECAlgorithmMapping = {
  sha1: DNSSECAlgorithm.RSASHA1,
  sha256: DNSSECAlgorithm.RSASHA256,
  sha512: DNSSECAlgorithm.RSASHA512,
};

const HASH_BY_CURVE: { readonly [curve: string]: string } = {
  prime256v1: 'sha256',
  secp384r1: 'sha384',
};

export function getDNSSECAlgoFromKey(publicOrPrivateKey: KeyObject): DNSSECAlgorithm {
  const keyType = publicOrPrivateKey.asymmetricKeyType!;
  const asymmetricKeyDetails = publicOrPrivateKey.asymmetricKeyDetails!;
  const hashAlgorithm = asymmetricKeyDetails.hashAlgorithm;

  let algorithm: DNSSECAlgorithm | null = null;
  if (keyType.startsWith('rsa')) {
    algorithm = RSA_ALGORITHMS_BY_HASH[hashAlgorithm!];
  } else if (keyType === 'dsa') {
    algorithm = DSA_ALGORITHMS_BY_HASH[hashAlgorithm!];
  } else if (keyType === 'ec') {
    const namedCurve = asymmetricKeyDetails.namedCurve;
    algorithm = ECDSA_ALGORITHMS_BY_CURVE[namedCurve!];
  } else if (keyType === 'ed25519') {
    algorithm = DNSSECAlgorithm.ED25519;
  } else if (keyType === 'ed448') {
    algorithm = DNSSECAlgorithm.ED448;
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

export function getNodejsHashAlgo(algorithm: DigestType): string {
  switch (algorithm) {
    case DigestType.SHA1:
      return 'sha1';
    case DigestType.SHA256:
      return 'sha256';
    case DigestType.SHA384:
      return 'sha384';
    default:
      throw new Error(`Unsupported hashing algorithm ${algorithm}`);
  }
}

export function derSerialisePublicKey(publicKey: KeyObject): Buffer {
  return publicKey.export({ format: 'der', type: 'spki' });
}
