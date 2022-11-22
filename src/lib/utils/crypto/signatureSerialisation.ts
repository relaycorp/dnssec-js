import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { toBigIntBE, toBufferBE } from 'bigint-buffer';

import { DnssecAlgorithm } from '../../DnssecAlgorithm';
import { EcdsaSignature } from './asn1Schemas/EcdsaSignature';
import { DnssecError } from '../../DnssecError';
import { ECDSA_CURVE_LENGTH } from './curves';

/**
 * Convert `originalSignature` to the format required by the respective DNSSEC RFC.
 *
 * @param originalSignature
 * @param algorithm
 */
export function convertSignatureToDnssec(
  originalSignature: Buffer,
  algorithm: DnssecAlgorithm,
): Buffer {
  switch (algorithm) {
    case DnssecAlgorithm.ECDSAP256SHA256:
    case DnssecAlgorithm.ECDSAP384SHA384:
      return convertEcdsaSignatureToDnssec(originalSignature, algorithm);
    default:
      return originalSignature;
  }
}

function convertEcdsaSignatureToDnssec(
  originalSignature: Buffer,
  algorithm: DnssecAlgorithm.ECDSAP256SHA256 | DnssecAlgorithm.ECDSAP384SHA384,
) {
  let signature: EcdsaSignature;
  try {
    signature = AsnParser.parse(originalSignature, EcdsaSignature);
  } catch (err) {
    throw new DnssecError('DER-encoded ECDSA signature is malformed');
  }
  const length = ECDSA_CURVE_LENGTH[algorithm] / 2;
  const rSerialised = toBufferBE(signature.r, length);
  const sSerialised = toBufferBE(signature.s, length);
  return Buffer.concat([rSerialised, sSerialised]);
}

/**
 * Convert `originalSignature` from the format specified in the respective DNSSEC RFC.
 *
 * @param dnssecSignature
 * @param algorithm
 */
export function convertSignatureFromDnssec(
  dnssecSignature: Buffer,
  algorithm: DnssecAlgorithm,
): Buffer {
  switch (algorithm) {
    case DnssecAlgorithm.ECDSAP256SHA256:
    case DnssecAlgorithm.ECDSAP384SHA384:
      return convertEcdsaSignatureFromDnssec(dnssecSignature, algorithm);
    default:
      return dnssecSignature;
  }
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

  const paramsLength = length / 2;
  const rSerialised = dnssecSignature.subarray(0, paramsLength);
  const sSerialised = dnssecSignature.subarray(paramsLength);
  const asn1Signature = new EcdsaSignature();
  asn1Signature.r = toBigIntBE(rSerialised);
  asn1Signature.s = toBigIntBE(sSerialised);
  const derSignature = AsnSerializer.serialize(asn1Signature);
  return Buffer.from(derSignature);
}
