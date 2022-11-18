import { createPublicKey, KeyObject } from 'node:crypto';
import { toBufferBE } from 'bigint-buffer';

import { getIntegerByteLength } from '../integers';
import { DnssecAlgorithm } from '../../DnssecAlgorithm';

export function serialisePublicKey(publicKey: KeyObject): Buffer {
  const algorithm = publicKey.asymmetricKeyType!;

  if (algorithm.startsWith('rsa')) {
    const exponent = publicKey.asymmetricKeyDetails!.publicExponent!;
    const exponentBuffer = toBufferBE(exponent, getIntegerByteLength(exponent));
    const exponentLengthPrefix = serialiseRsaExponentPrefix(exponentBuffer);

    const keyJwt = publicKey.export({ format: 'jwk' });
    const modulusBuffer = Buffer.from(keyJwt.n as string, 'base64');

    return Buffer.concat([exponentLengthPrefix, exponentBuffer, modulusBuffer]);
  }

  throw new Error(`Unsupported algorithm (${algorithm})`);
}

function serialiseRsaExponentPrefix(exponent: Buffer): Buffer {
  const exponentLength = exponent.byteLength;
  let prefix: Buffer;
  if (exponentLength < 256) {
    // Length fits in one octet
    prefix = Buffer.from([exponentLength]);
  } else {
    // We'll need two octets to represent the length
    prefix = Buffer.allocUnsafe(3);
    prefix.writeUInt8(0, 0);
    prefix.writeUInt16BE(exponentLength, 1);
  }
  return prefix;
}

export function deserialisePublicKey(
  serialisation: Buffer,
  dnssecAlgorithm: DnssecAlgorithm,
): KeyObject {
  switch (dnssecAlgorithm) {
    case DnssecAlgorithm.RSASHA1:
    case DnssecAlgorithm.RSASHA256:
    case DnssecAlgorithm.RSASHA512:
      return deserialiseRsaPublicKey(serialisation);
    default:
      throw new Error(`Unsupported algorithm (${dnssecAlgorithm})`);
  }
}

function deserialiseRsaPublicKey(serialisation: Buffer) {
  const serialisationLength = serialisation.byteLength;
  if (serialisationLength < 3) {
    throw new Error(`Public key should contain at least 3 octets (got ${serialisationLength})`);
  }
  const isExponentSingleOctet = serialisation[0] !== 0;
  const exponentLength = isExponentSingleOctet
    ? serialisation.readUInt8(0)
    : serialisation.readUInt16BE(1);
  const exponentStartIndex = isExponentSingleOctet ? 1 : 3;
  const modulusStartIndex = exponentStartIndex + exponentLength;
  const exponentBuffer = serialisation.subarray(exponentStartIndex, modulusStartIndex);
  const modulusBuffer = serialisation.subarray(modulusStartIndex);
  return createPublicKey({
    key: {
      n: modulusBuffer.toString('base64url'),
      e: exponentBuffer.toString('base64url'),
      kty: 'RSA',
    },
    format: 'jwk',
  });
}
