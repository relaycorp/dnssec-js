import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { bigintToBuf, bufToBigint } from 'bigint-conversion';

import { DnssecAlgorithm } from '../../DnssecAlgorithm.js';
import { DnssecError } from '../../DnssecError.js';

import { EcdsaSignature } from './EcdsaSignature.js';
import { ECDSA_CURVE_LENGTH } from './curves.js';

function convertEcdsaSignatureToDnssec(originalSignature: Buffer): Buffer {
  let signature: EcdsaSignature;
  try {
    signature = AsnParser.parse(originalSignature, EcdsaSignature);
  } catch {
    throw new DnssecError('DER-encoded ECDSA signature is malformed');
  }
  const rSerialised = bigintToBuf(signature.rParam) as Buffer;
  const sSerialised = bigintToBuf(signature.sParam) as Buffer;
  return Buffer.concat([rSerialised, sSerialised]);
}

function convertEcdsaSignatureFromDnssec(
  dnssecSignature: Buffer,
  algorithm: DnssecAlgorithm.ECDSAP256SHA256 | DnssecAlgorithm.ECDSAP384SHA384,
): Buffer {
  const length = dnssecSignature.byteLength;
  const expectedLength = ECDSA_CURVE_LENGTH[algorithm];
  if (length !== expectedLength) {
    throw new DnssecError(`ECDSA signature should span ${expectedLength} octets (got ${length})`);
  }

  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  const parametersLength = length / 2;
  const rSerialised = dnssecSignature.subarray(0, parametersLength);
  const sSerialised = dnssecSignature.subarray(parametersLength);
  const asn1Signature = new EcdsaSignature();
  asn1Signature.rParam = bufToBigint(rSerialised);
  asn1Signature.sParam = bufToBigint(sSerialised);
  const derSignature = AsnSerializer.serialize(asn1Signature);
  return Buffer.from(derSignature);
}

/**
 * Convert `originalSignature` to the format required by the respective DNSSEC RFC.
 */
export function convertSignatureToDnssec(
  originalSignature: Buffer,
  algorithm: DnssecAlgorithm,
): Buffer {
  switch (algorithm) {
    case DnssecAlgorithm.ECDSAP256SHA256:
    case DnssecAlgorithm.ECDSAP384SHA384: {
      return convertEcdsaSignatureToDnssec(originalSignature);
    }
    default: {
      return originalSignature;
    }
  }
}

/**
 * Convert `originalSignature` from the format specified in the respective DNSSEC RFC.
 */
export function convertSignatureFromDnssec(
  dnssecSignature: Buffer,
  algorithm: DnssecAlgorithm,
): Buffer {
  switch (algorithm) {
    case DnssecAlgorithm.ECDSAP256SHA256:
    case DnssecAlgorithm.ECDSAP384SHA384: {
      return convertEcdsaSignatureFromDnssec(dnssecSignature, algorithm);
    }
    default: {
      return dnssecSignature;
    }
  }
}
