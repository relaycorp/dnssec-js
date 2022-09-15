import { KeyObject } from 'node:crypto';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';
import { DigestAlgorithm } from '../DigestAlgorithm';

export function getDNSSECAlgoFromKey(_publicOrPrivateKey: KeyObject): DNSSECAlgorithm {
  // TODO: Support more algorithms
  return DNSSECAlgorithm.RSASHA256;
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
