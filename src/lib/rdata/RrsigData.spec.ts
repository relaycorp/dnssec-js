import { addMinutes, setMilliseconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { SignatureGenerationOptions, ZoneSigner } from '../signing/ZoneSigner';
import { RrsigData } from './RrsigData';
import { InvalidRdataError } from '../errors';
import { serialiseName } from '../dns/name';
import { RRSet } from '../dns/RRSet';
import { QUESTION, RECORD, RRSET } from '../../testUtils/dnsStubs';

describe('RrsigData', () => {
  const ALGORITHM = DnssecAlgorithm.RSASHA256;
  const STUB_KEY_TAG = 12345;

  const NOW = setMilliseconds(new Date(), 0);
  const SIGNATURE_OPTIONS: SignatureGenerationOptions = {
    signatureExpiry: addMinutes(NOW, 10),
    signatureInception: NOW,
  };

  let signer: ZoneSigner;
  beforeAll(async () => {
    signer = await ZoneSigner.generate(ALGORITHM, RECORD.name);
  });

  describe('deserialise', () => {
    test('Malformed value should be refused', () => {
      // 18 octets means that the Signer's Name and Signature are missing
      const malformedRrsigData = Buffer.allocUnsafe(18);

      expect(() => RrsigData.deserialise(malformedRrsigData)).toThrowWithMessage(
        InvalidRdataError,
        'RRSIG data is malformed',
      );
    });

    test('Empty signature should be refused', () => {
      const nameSerialised = serialiseName(RECORD.name);
      const serialisation = Buffer.allocUnsafe(18 + nameSerialised.byteLength);
      nameSerialised.copy(serialisation, 18);

      expect(() => RrsigData.deserialise(serialisation)).toThrowWithMessage(
        InvalidRdataError,
        'Signature is empty',
      );
    });

    test('Record type should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.type).toEqual(RECORD.type);
    });

    test('Algorithm should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.algorithm).toEqual(ALGORITHM);
    });

    test('Labels should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      const expectedLabelCount = RRSET.name.replace(/\.$/, '').split('.').length;
      expect(rrsigData.labels).toEqual(expectedLabelCount);
    });

    test('TTL should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.ttl).toEqual(RRSET.ttl);
    });

    test('Signature expiry date should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureExpiry).toEqual(SIGNATURE_OPTIONS.signatureExpiry);
    });

    test('Signature inception date should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureInception).toEqual(SIGNATURE_OPTIONS.signatureInception);
    });

    test('Key tag should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.keyTag).toEqual(STUB_KEY_TAG);
    });

    test('Signer name should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signerName).toEqual(signer.zoneName);
    });

    test('Signature should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signature).toEqual(rrsig.data.signature);
    });
  });

  describe('verifyRrset', () => {
    test('Covered type should match RRset type', () => {
      const type = RECORD.type + 1;
      const invalidRrset = RRSet.init(QUESTION.shallowCopy({ type }), [
        RECORD.shallowCopy({ type }),
      ]);
      const { data } = signer.generateRrsig(invalidRrset, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      expect(data.verifyRrset(RRSET, signer.publicKey)).toBeFalse();
    });

    test('Original TTL should match RRset TTL', () => {
      const invalidRrset = RRSet.init(QUESTION, [RECORD.shallowCopy({ ttl: RECORD.ttl + 1 })]);
      const { data } = signer.generateRrsig(invalidRrset, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      expect(data.verifyRrset(RRSET, signer.publicKey)).toBeFalse();
    });

    describe('Label count', () => {
      test('RRset owner labels greater than RRSig count should be SECURE', async () => {
        const name = `subdomain.${RECORD.name}`;
        const differentRrset = RRSet.init(QUESTION.shallowCopy({ name }), [
          RECORD.shallowCopy({ name }),
        ]);
        const { data } = signer.generateRrsig(differentRrset, STUB_KEY_TAG, SIGNATURE_OPTIONS);

        expect(data.verifyRrset(differentRrset, signer.publicKey)).toBeTrue();
      });

      test('RRset owner labels equal to RRSig count should be SECURE', () => {
        const { data } = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

        expect(data.verifyRrset(RRSET, signer.publicKey)).toBeTrue();
      });

      test('RRset owner labels less than RRSig count should be BOGUS', async () => {
        const { data } = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);
        const mismatchingData = new RrsigData(
          data.type,
          data.algorithm,
          data.labels + 1,
          data.ttl,
          data.signatureExpiry,
          data.signatureInception,
          data.keyTag,
          data.signerName,
          data.signature,
        );

        expect(mismatchingData.verifyRrset(RRSET, signer.publicKey)).toBeFalse();
      });
    });

    test('Invalid signature should be BOGUS', () => {
      const { data } = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);
      const mismatchingData = new RrsigData(
        data.type,
        data.algorithm,
        data.labels,
        data.ttl,
        data.signatureExpiry,
        data.signatureInception,
        data.keyTag,
        data.signerName,
        data.signature.subarray(1),
      );

      expect(mismatchingData.verifyRrset(RRSET, signer.publicKey)).toBeFalse();
    });

    test('Valid RRset should be SECURE', () => {
      const { data } = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      expect(data.verifyRrset(RRSET, signer.publicKey)).toBeTrue();
    });
  });
});
