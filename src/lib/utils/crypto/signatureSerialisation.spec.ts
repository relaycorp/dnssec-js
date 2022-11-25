import { AsnProp, AsnPropTypes, AsnSerializer } from '@peculiar/asn1-schema';
import { toBigIntBE } from 'bigint-buffer';

import { DnssecAlgorithm } from '../../DnssecAlgorithm';
import { DnssecError } from '../../DnssecError';

import { convertSignatureFromDnssec, convertSignatureToDnssec } from './signatureSerialisation';
import { EcdsaSignature } from './asn1Schemas/EcdsaSignature';

// Parameters taken from https://www.rfc-editor.org/rfc/rfc6605.html#section-6
const ECDSA_SIGNATURES = {
  p256: Buffer.from(
    'qx6wLYqmh-l9oCKTN6qIc-bw6ya-KJ8oMz0YP107epXAyGmt-3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw',
    'base64url',
  ),

  p384: Buffer.from(
    '_L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSS' +
      'Pdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm',
    'base64url',
  ),
};

describe('convertSignatureToDnssec', () => {
  test('RSA signatures should be returned unchanged', () => {
    const stubSignature = Buffer.allocUnsafe(5);

    expect(convertSignatureToDnssec(stubSignature, DnssecAlgorithm.RSASHA1)).toBe(stubSignature);
    expect(convertSignatureToDnssec(stubSignature, DnssecAlgorithm.RSASHA256)).toBe(stubSignature);
    expect(convertSignatureToDnssec(stubSignature, DnssecAlgorithm.RSASHA512)).toBe(stubSignature);
  });

  describe('ECDSA', () => {
    test('P-256 signature should be converted to 64-octet buffer', () => {
      const totalLength = 64;
      const rSerialisation = ECDSA_SIGNATURES.p256.subarray(0, totalLength / 2);
      const sSerialisation = ECDSA_SIGNATURES.p256.subarray(totalLength / 2);
      const asn1Signature = new EcdsaSignature();
      asn1Signature.r = toBigIntBE(rSerialisation);
      asn1Signature.s = toBigIntBE(sSerialisation);
      const derSignature = Buffer.from(AsnSerializer.serialize(asn1Signature));

      const dnssecSerialisation = convertSignatureToDnssec(
        derSignature,
        DnssecAlgorithm.ECDSAP256SHA256,
      );

      expect(dnssecSerialisation.byteLength).toEqual(totalLength);
      expect(dnssecSerialisation).toEqual(Buffer.concat([rSerialisation, sSerialisation]));
    });

    test('P-384 signature should be converted to 96-octet buffer', () => {
      const totalLength = 96;
      const rSerialisation = ECDSA_SIGNATURES.p384.subarray(0, totalLength / 2);
      const sSerialisation = ECDSA_SIGNATURES.p384.subarray(totalLength / 2);
      const asn1Signature = new EcdsaSignature();
      asn1Signature.r = toBigIntBE(rSerialisation);
      asn1Signature.s = toBigIntBE(sSerialisation);
      const derSignature = Buffer.from(AsnSerializer.serialize(asn1Signature));

      const dnssecSerialisation = convertSignatureToDnssec(
        derSignature,
        DnssecAlgorithm.ECDSAP384SHA384,
      );

      expect(dnssecSerialisation.byteLength).toEqual(totalLength);
      expect(dnssecSerialisation).toEqual(Buffer.concat([rSerialisation, sSerialisation]));
    });

    test('Malformed DER values should be refused', () => {
      const serialisation = Buffer.from('Not DER');

      expect(() =>
        convertSignatureToDnssec(serialisation, DnssecAlgorithm.ECDSAP256SHA256),
      ).toThrowWithMessage(DnssecError, 'DER-encoded ECDSA signature is malformed');
    });

    test('Invalid DER values should be refused', () => {
      class Schema {
        @AsnProp({ type: AsnPropTypes.Null })
        public foo = null;
      }
      const serialisation = Buffer.from(AsnSerializer.serialize(new Schema()));

      expect(() =>
        convertSignatureToDnssec(serialisation, DnssecAlgorithm.ECDSAP256SHA256),
      ).toThrowWithMessage(DnssecError, 'DER-encoded ECDSA signature is malformed');
    });
  });

  test('EdDSA signatures should be returned unchanged', () => {
    const stubSignature = Buffer.allocUnsafe(5);

    expect(convertSignatureToDnssec(stubSignature, DnssecAlgorithm.ED25519)).toBe(stubSignature);
    expect(convertSignatureToDnssec(stubSignature, DnssecAlgorithm.ED448)).toBe(stubSignature);
  });
});

describe('convertSignatureFromDnssec', () => {
  test('RSA signatures should be returned unchanged', () => {
    const stubSignature = Buffer.allocUnsafe(5);

    expect(convertSignatureFromDnssec(stubSignature, DnssecAlgorithm.RSASHA1)).toBe(stubSignature);
    expect(convertSignatureFromDnssec(stubSignature, DnssecAlgorithm.RSASHA256)).toBe(
      stubSignature,
    );
    expect(convertSignatureFromDnssec(stubSignature, DnssecAlgorithm.RSASHA512)).toBe(
      stubSignature,
    );
  });

  describe('ECDSA', () => {
    test('P-256 signature should be converted to DER SEQUENCE', () => {
      const algorithm = DnssecAlgorithm.ECDSAP256SHA256;

      const derSignature = convertSignatureFromDnssec(ECDSA_SIGNATURES.p256, algorithm);

      expect(convertSignatureToDnssec(derSignature, algorithm)).toEqual(ECDSA_SIGNATURES.p256);
    });

    test('P-256 signature should be refused if it does not span 64 octets', () => {
      const invalidSignature = Buffer.allocUnsafe(63);
      const algorithm = DnssecAlgorithm.ECDSAP256SHA256;

      expect(() => convertSignatureFromDnssec(invalidSignature, algorithm)).toThrowWithMessage(
        DnssecError,
        `ECDSA signature should span 64 octets (got ${invalidSignature.byteLength})`,
      );
    });

    test('P-384 signature should be converted to DER SEQUENCE', () => {
      const algorithm = DnssecAlgorithm.ECDSAP384SHA384;

      const derSignature = convertSignatureFromDnssec(ECDSA_SIGNATURES.p384, algorithm);

      expect(convertSignatureToDnssec(derSignature, algorithm)).toEqual(ECDSA_SIGNATURES.p384);
    });

    test('P-384 signature should be refused if it does not span 96 octets', () => {
      const invalidSignature = Buffer.allocUnsafe(95);
      const algorithm = DnssecAlgorithm.ECDSAP384SHA384;

      expect(() => convertSignatureFromDnssec(invalidSignature, algorithm)).toThrowWithMessage(
        DnssecError,
        `ECDSA signature should span 96 octets (got ${invalidSignature.byteLength})`,
      );
    });
  });

  test('EdDSA signatures should be returned unchanged', () => {
    const stubSignature = Buffer.allocUnsafe(5);

    expect(convertSignatureFromDnssec(stubSignature, DnssecAlgorithm.ED25519)).toBe(stubSignature);
    expect(convertSignatureFromDnssec(stubSignature, DnssecAlgorithm.ED448)).toBe(stubSignature);
  });
});
