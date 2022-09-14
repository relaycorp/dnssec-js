import { KeyObject } from 'node:crypto';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';

export function getDNSSECAlgorithm(_publicKey: KeyObject): DNSSECAlgorithm {
  // TODO: Support more algorithms
  return DNSSECAlgorithm.RSASHA256;
}

export function derSerialisePublicKey(publicKey: KeyObject): Buffer {
  return publicKey.export({ format: 'der', type: 'spki' });
}
