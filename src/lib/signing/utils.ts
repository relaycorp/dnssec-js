import { KeyObject } from 'node:crypto';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';
import { DigestAlgorithm } from '../DigestAlgorithm';

const DSA_ALGORITHMS_BY_HASH: { readonly [key: string]: DNSSECAlgorithm } = {
  sha1: DNSSECAlgorithm.DSA,
};

const RSA_ALGORITHMS_BY_HASH: { readonly [key: string]: DNSSECAlgorithm } = {
  sha1: DNSSECAlgorithm.RSASHA1,
  sha256: DNSSECAlgorithm.RSASHA256,
};

export function getDNSSECAlgoFromKey(publicOrPrivateKey: KeyObject): DNSSECAlgorithm {
  const keyType = publicOrPrivateKey.asymmetricKeyType!;
  const hashAlgorithm = publicOrPrivateKey.asymmetricKeyDetails!.hashAlgorithm!;
  let algorithm: DNSSECAlgorithm | null = null;

  if (keyType.startsWith('rsa')) {
    algorithm = RSA_ALGORITHMS_BY_HASH[hashAlgorithm];
  } else if (keyType === 'dsa') {
    algorithm = DSA_ALGORITHMS_BY_HASH[hashAlgorithm];
  }

  if (!algorithm) {
    throw new Error(`Unsupported algorithm (${keyType}, ${hashAlgorithm})`);
  }
  return algorithm;
}

export function getNodejsHashAlgo(algorithm: DigestAlgorithm): string {
  switch (algorithm) {
    case DigestAlgorithm.SHA1:
      return 'sha1';
    case DigestAlgorithm.SHA256:
      return 'sha256';
    case DigestAlgorithm.SHA384:
      return 'sha384';
    default:
      throw new Error(`Unsupported hashing algorithm ${algorithm}`);
  }
}

export function derSerialisePublicKey(publicKey: KeyObject): Buffer {
  return publicKey.export({ format: 'der', type: 'spki' });
}
