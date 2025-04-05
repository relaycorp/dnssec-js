import { createPublicKey, type KeyObject } from 'node:crypto';

import { bigintToBuf } from 'bigint-conversion';

import { DnssecAlgorithm } from '../../DnssecAlgorithm.js';
import { DnssecError } from '../../DnssecError.js';

import { ECDSA_CURVE_LENGTH, EDDSA_SERIALISED_KEY_LENGTH } from './curves.js';

const RSA_SINGLE_OCTET_THRESHOLD = 256;
const RSA_MULTI_OCTET_PREFIX_LENGTH = 3;

function serialiseRsaExponentPrefix(exponent: Buffer): Buffer {
  const exponentLength = exponent.byteLength;
  let prefix: Buffer;
  if (exponentLength < RSA_SINGLE_OCTET_THRESHOLD) {
    // Length fits in one octet
    prefix = Buffer.from([exponentLength]);
  } else {
    // We'll need two octets to represent the length
    prefix = Buffer.allocUnsafe(RSA_MULTI_OCTET_PREFIX_LENGTH);
    prefix.writeUInt8(0, 0);
    prefix.writeUInt16BE(exponentLength, 1);
  }
  return prefix;
}

function serialiseRsaPublicKey(publicKey: KeyObject): Buffer {
  const algorithm = publicKey.asymmetricKeyType!;
  if (!algorithm.startsWith('rsa')) {
    throw new Error(`Requested serialisation of RSA key but got ${algorithm} key`);
  }

  const exponent = publicKey.asymmetricKeyDetails!.publicExponent!;
  const exponentBuffer = bigintToBuf(exponent) as Buffer;
  const exponentLengthPrefix = serialiseRsaExponentPrefix(exponentBuffer);

  const keyJwt = publicKey.export({ format: 'jwk' });
  const modulusBuffer = Buffer.from(keyJwt.n!, 'base64');

  return Buffer.concat([exponentLengthPrefix, exponentBuffer, modulusBuffer]);
}

function serialiseEcDsaPublicKey(publicKey: KeyObject): Buffer {
  const algorithm = publicKey.asymmetricKeyType!;
  if (algorithm !== 'ec') {
    throw new Error(`Requested serialisation of ECDSA key but got ${algorithm} key`);
  }

  const keyJwt = publicKey.export({ format: 'jwk' });
  const xBuffer = Buffer.from(keyJwt.x!, 'base64url');
  const yBuffer = Buffer.from(keyJwt.y!, 'base64url');
  return Buffer.concat([xBuffer, yBuffer]);
}

function serialiseEdDsaPublicKey(publicKey: KeyObject): Buffer {
  const algorithm = publicKey.asymmetricKeyType!;
  if (!['ed25519', 'ed448'].includes(algorithm)) {
    throw new Error(`Requested serialisation of EdDSA key but got ${algorithm} key`);
  }
  const keyJwt = publicKey.export({ format: 'jwk' });
  return Buffer.from(keyJwt.x!, 'base64url');
}

function deserialiseRsaPublicKey(serialisation: Buffer): KeyObject {
  const serialisationLength = serialisation.byteLength;
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  if (serialisationLength < 3) {
    throw new Error(`Public key should contain at least 3 octets (got ${serialisationLength})`);
  }
  const isExponentSingleOctet = serialisation[0] !== 0;
  const exponentLength = isExponentSingleOctet
    ? serialisation.readUInt8(0)
    : serialisation.readUInt16BE(1);
  const exponentStartIndex = isExponentSingleOctet ? 1 : RSA_MULTI_OCTET_PREFIX_LENGTH;
  const modulusStartIndex = exponentStartIndex + exponentLength;
  const exponentBuffer = serialisation.subarray(exponentStartIndex, modulusStartIndex);
  const modulusBuffer = serialisation.subarray(modulusStartIndex);
  return createPublicKey({
    key: {
      // eslint-disable-next-line id-length
      n: modulusBuffer.toString('base64url'),
      // eslint-disable-next-line id-length
      e: exponentBuffer.toString('base64url'),
      kty: 'RSA',
    },

    format: 'jwk',
  });
}

function deserialiseEcDsaPublicKey(
  serialisation: Buffer,
  algorithm: DnssecAlgorithm.ECDSAP256SHA256 | DnssecAlgorithm.ECDSAP384SHA384,
): KeyObject {
  const length = serialisation.byteLength;
  const expectedLength = ECDSA_CURVE_LENGTH[algorithm];
  if (length !== expectedLength) {
    throw new DnssecError(`ECDSA public key should span ${expectedLength} octets (got ${length})`);
  }

  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  const parametersLength = length / 2;
  const xParameter = serialisation.subarray(0, parametersLength).toString('base64url');
  const yParameter = serialisation.subarray(parametersLength).toString('base64url');
  const curveName = algorithm === DnssecAlgorithm.ECDSAP256SHA256 ? 'P-256' : 'P-384';
  return createPublicKey({
    // eslint-disable-next-line id-length
    key: { kty: 'EC', crv: curveName, x: xParameter, y: yParameter },
    format: 'jwk',
  });
}

function deserialiseEdDsaPublicKey(
  serialisation: Buffer,
  algorithm: DnssecAlgorithm.ED448 | DnssecAlgorithm.ED25519,
): KeyObject {
  const serialisationLength = serialisation.byteLength;
  const expectedLength = EDDSA_SERIALISED_KEY_LENGTH[algorithm];
  if (serialisationLength !== expectedLength) {
    throw new Error(
      `EdDSA public key should span ${expectedLength} octets (got ${serialisationLength})`,
    );
  }

  const curveName = algorithm === DnssecAlgorithm.ED25519 ? 'Ed25519' : 'Ed448';
  const publicKeyBase64 = serialisation.toString('base64url');
  return createPublicKey({
    // eslint-disable-next-line id-length
    key: { crv: curveName, kty: 'OKP', x: publicKeyBase64 },
    format: 'jwk',
  });
}

export function serialisePublicKey(publicKey: KeyObject, dnssecAlgorithm: DnssecAlgorithm): Buffer {
  switch (dnssecAlgorithm) {
    case DnssecAlgorithm.RSASHA1:
    case DnssecAlgorithm.RSASHA256:
    case DnssecAlgorithm.RSASHA512: {
      return serialiseRsaPublicKey(publicKey);
    }
    case DnssecAlgorithm.ECDSAP256SHA256:
    case DnssecAlgorithm.ECDSAP384SHA384: {
      return serialiseEcDsaPublicKey(publicKey);
    }
    case DnssecAlgorithm.ED25519:
    case DnssecAlgorithm.ED448: {
      return serialiseEdDsaPublicKey(publicKey);
    }
    default: {
      throw new Error(`Unsupported DNSSEC algorithm (${dnssecAlgorithm as number})`);
    }
  }
}

export function deserialisePublicKey(
  serialisation: Buffer,
  dnssecAlgorithm: DnssecAlgorithm,
): KeyObject {
  switch (dnssecAlgorithm) {
    case DnssecAlgorithm.RSASHA1:
    case DnssecAlgorithm.RSASHA256:
    case DnssecAlgorithm.RSASHA512: {
      return deserialiseRsaPublicKey(serialisation);
    }
    case DnssecAlgorithm.ECDSAP256SHA256:
    case DnssecAlgorithm.ECDSAP384SHA384: {
      return deserialiseEcDsaPublicKey(serialisation, dnssecAlgorithm);
    }
    case DnssecAlgorithm.ED25519:
    case DnssecAlgorithm.ED448: {
      return deserialiseEdDsaPublicKey(serialisation, dnssecAlgorithm);
    }
    default: {
      throw new Error(`Unsupported DNSSEC algorithm (${dnssecAlgorithm as number})`);
    }
  }
}
