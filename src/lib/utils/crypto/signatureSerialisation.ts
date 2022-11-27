import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { toBigIntBE, toBufferBE } from 'bigint-buffer';

import { DnssecAlgorithm } from '../../DnssecAlgorithm.js';
import { DnssecError } from '../../DnssecError.js';

import { EcdsaSignature } from './asn1Schemas/EcdsaSignature.js';
import { ECDSA_CURVE_LENGTH } from './curves.js';

function convertEcdsaSignatureToDnssec(
  originalSignature: Buffer,
  algorithm: DnssecAlgorithm.ECDSAP256SHA256 | DnssecAlgorithm.ECDSAP384SHA384,
) {
  let signature: EcdsaSignature;
  try {
    signature = AsnParser.parse(originalSignature, EcdsaSignature);
  } catch {
    throw new DnssecError('DER-encoded ECDSA signature is malformed');
  }
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  const length = ECDSA_CURVE_LENGTH[algorithm] / 2;
  const rSerialised = toBufferBE(signature.rParam, length);
  const sSerialised = toBufferBE(signature.sParam, length);
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
  asn1Signature.rParam = toBigIntBE(rSerialised);
  asn1Signature.sParam = toBigIntBE(sSerialised);
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
      return convertEcdsaSignatureToDnssec(originalSignature, algorithm);
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
