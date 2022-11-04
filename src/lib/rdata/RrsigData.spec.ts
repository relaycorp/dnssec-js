import { addMinutes, setMilliseconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { ZoneSigner } from '../signing/ZoneSigner';
import { RrsigData } from './RrsigData';
import { InvalidRdataError } from '../errors';
import { serialiseName } from '../dns/name';
import { RRSet } from '../dns/RRSet';
import { RECORD, RECORD_TLD } from '../../testUtils/stubs';
import { SecurityStatus } from '../verification/SecurityStatus';

describe('RrsigData', () => {
  const ALGORITHM = DnssecAlgorithm.RSASHA256;
  const STUB_KEY_TAG = 12345;

  const signatureInception = setMilliseconds(new Date(), 0);
  const signatureExpiry = addMinutes(signatureInception, 10);

  let tldSigner: ZoneSigner;
  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(ALGORITHM, RECORD_TLD);
  });

  describe('deserialise', () => {
    const rrset = new RRSet([RECORD]);

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
      const rrsig = tldSigner.generateRrsig(rrset, STUB_KEY_TAG, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.type).toEqual(RECORD.type);
    });

    test('Algorithm should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, STUB_KEY_TAG, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.algorithm).toEqual(ALGORITHM);
    });

    test('Labels should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, STUB_KEY_TAG, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      const expectedLabelCount = rrset.name.replace(/\.$/, '').split('.').length;
      expect(rrsigData.labels).toEqual(expectedLabelCount);
    });

    test('TTL should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, STUB_KEY_TAG, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.ttl).toEqual(rrset.ttl);
    });

    test('Signature expiry date should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, STUB_KEY_TAG, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureExpiry).toEqual(signatureExpiry);
    });

    test('Signature inception date should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(
        rrset,
        STUB_KEY_TAG,
        signatureExpiry,
        signatureInception,
      );

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureInception).toEqual(signatureInception);
    });

    test('Key tag should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(
        rrset,
        STUB_KEY_TAG,
        signatureExpiry,
        signatureInception,
      );

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.keyTag).toEqual(STUB_KEY_TAG);
    });

    test('Signer name should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(
        rrset,
        STUB_KEY_TAG,
        signatureExpiry,
        signatureInception,
      );

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signerName).toEqual(tldSigner.zoneName);
    });

    test('Signature should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(
        rrset,
        STUB_KEY_TAG,
        signatureExpiry,
        signatureInception,
      );

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signature.byteLength).toBeGreaterThan(0);
    });
  });

  describe('verifyRrset', () => {
    const rrset = new RRSet([RECORD]);

    describe('Signer name', () => {
      test('Signer name matching RRset parent zone should be SECURE', async () => {
        const { data } = tldSigner.generateRrsig(
          rrset,
          STUB_KEY_TAG,
          signatureExpiry,
          signatureInception,
        );

        expect(data.verifyRrset(rrset)).toEqual(SecurityStatus.SECURE);
      });

      test('Signer name mismatching RRset parent zone should be BOGUS', async () => {
        const differentParent = await ZoneSigner.generate(ALGORITHM, `not-${RECORD_TLD}`);
        const { data } = differentParent.generateRrsig(
          rrset,
          STUB_KEY_TAG,
          signatureExpiry,
          signatureInception,
        );

        expect(data.verifyRrset(rrset)).toEqual(SecurityStatus.BOGUS);
      });

      test('TLD RRset should be supported', async () => {
        const rootSigner = await ZoneSigner.generate(ALGORITHM, '.');
        const tldRrset = new RRSet([RECORD.shallowCopy({ name: RECORD_TLD })]);
        const { data } = rootSigner.generateRrsig(
          tldRrset,
          STUB_KEY_TAG,
          signatureExpiry,
          signatureInception,
        );

        expect(data.verifyRrset(tldRrset)).toEqual(SecurityStatus.SECURE);
      });
    });

    test('Covered type should match RRset type', () => {
      const invalidRrset = new RRSet([RECORD.shallowCopy({ type: RECORD.type + 1 })]);
      const { data } = tldSigner.generateRrsig(
        invalidRrset,
        STUB_KEY_TAG,
        signatureExpiry,
        signatureInception,
      );

      expect(data.verifyRrset(rrset)).toEqual(SecurityStatus.BOGUS);
    });

    test('Original TTL should match RRset TTL', () => {
      const invalidRrset = new RRSet([RECORD.shallowCopy({ ttl: RECORD.ttl + 1 })]);
      const { data } = tldSigner.generateRrsig(
        invalidRrset,
        STUB_KEY_TAG,
        signatureExpiry,
        signatureInception,
      );

      expect(data.verifyRrset(rrset)).toEqual(SecurityStatus.BOGUS);
    });

    describe('Label count', () => {
      test('Count greater than actual number should be SECURE', async () => {
        const differentRrset = new RRSet([
          RECORD.shallowCopy({ name: `subdomain.${RECORD.name}` }),
        ]);
        const signer = await ZoneSigner.generate(ALGORITHM, RECORD.name);
        const { data } = signer.generateRrsig(
          differentRrset,
          STUB_KEY_TAG,
          signatureExpiry,
          signatureInception,
        );

        expect(data.verifyRrset(differentRrset)).toEqual(SecurityStatus.SECURE);
      });

      test('Count equal to actual number should be SECURE', () => {
        const differentRrset = new RRSet([RECORD]);
        const { data } = tldSigner.generateRrsig(
          differentRrset,
          STUB_KEY_TAG,
          signatureExpiry,
          signatureInception,
        );

        expect(data.verifyRrset(differentRrset)).toEqual(SecurityStatus.SECURE);
      });

      test('Count less than actual number should be BOGUS', async () => {
        const differentRrset = new RRSet([RECORD]);
        const { data } = tldSigner.generateRrsig(
          differentRrset,
          STUB_KEY_TAG,
          signatureExpiry,
          signatureInception,
        );
        const mismatchingData = new RrsigData(
          data.type,
          data.algorithm,
          data.labels - 1,
          data.ttl,
          data.signatureExpiry,
          data.signatureInception,
          data.keyTag,
          data.signerName,
          data.signature,
        );

        expect(mismatchingData.verifyRrset(differentRrset)).toEqual(SecurityStatus.BOGUS);
      });
    });

    test('Valid RRset should be SECURE', () => {
      const { data } = tldSigner.generateRrsig(
        rrset,
        STUB_KEY_TAG,
        signatureExpiry,
        signatureInception,
      );

      expect(data.verifyRrset(rrset)).toEqual(SecurityStatus.SECURE);
    });
  });
});
