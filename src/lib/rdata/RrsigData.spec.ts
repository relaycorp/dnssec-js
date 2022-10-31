import { addMinutes, addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { ZoneSigner } from '../signing/ZoneSigner';
import { RrsigData } from './RrsigData';
import { InvalidRdataError } from '../errors';
import { serialiseName } from '../dns/name';
import { RRSet } from '../dns/RRSet';
import { RECORD, RECORD_TLD } from '../../testUtils/stubs';
import { SecurityStatus } from '../verification/SecurityStatus';

describe('RrsigData', () => {
  const algorithm = DnssecAlgorithm.RSASHA256;
  const signatureInception = setMilliseconds(new Date(), 0);
  const signatureExpiry = addMinutes(signatureInception, 10);

  let tldSigner: ZoneSigner;
  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(algorithm, RECORD_TLD);
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
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.type).toEqual(RECORD.type);
    });

    test('Algorithm should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.algorithm).toEqual(algorithm);
    });

    test('Labels should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      const expectedLabelCount = rrset.name.replace(/\.$/, '').split('.').length;
      expect(rrsigData.labels).toEqual(expectedLabelCount);
    });

    test('TTL should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.ttl).toEqual(rrset.ttl);
    });

    test('Signature expiry date should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureExpiry).toEqual(signatureExpiry);
    });

    test('Signature inception date should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureInception).toEqual(signatureInception);
    });

    test('Key tag should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.keyTag).toEqual(tldSigner.keyTag);
    });

    test('Signer name should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signerName).toEqual(tldSigner.zoneName);
    });

    test('Signature should be extracted', () => {
      const rrsig = tldSigner.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signature.byteLength).toBeGreaterThan(0);
    });
  });

  describe('verifyRrset', () => {
    const rrset = new RRSet([RECORD]);
    const now = setMilliseconds(new Date(), 0);

    describe('Signer name', () => {
      test('Signer name matching RRset parent zone should be SECURE', async () => {
        const { data } = tldSigner.generateRrsig(rrset, signatureExpiry, signatureInception);

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Signer name mismatching RRset parent zone should be BOGUS', async () => {
        const differentParent = await ZoneSigner.generate(algorithm, `not-${RECORD_TLD}`);
        const { data } = differentParent.generateRrsig(rrset, signatureExpiry, signatureInception);

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.BOGUS);
      });

      test('TLD RRset should be supported', async () => {
        const rootSigner = await ZoneSigner.generate(algorithm, '.');
        const tldRrset = new RRSet([RECORD.shallowCopy({ name: RECORD_TLD })]);
        const { data } = rootSigner.generateRrsig(tldRrset, signatureExpiry, signatureInception);

        expect(data.verifyRrset(tldRrset, now)).toEqual(SecurityStatus.SECURE);
      });
    });

    test('Covered type should match RRset type', () => {
      const invalidRrset = new RRSet([RECORD.shallowCopy({ type: RECORD.type + 1 })]);
      const { data } = tldSigner.generateRrsig(invalidRrset, signatureExpiry, signatureInception);

      expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.BOGUS);
    });

    test('Original TTL should match RRset TTL', () => {
      const invalidRrset = new RRSet([RECORD.shallowCopy({ ttl: RECORD.ttl + 1 })]);
      const { data } = tldSigner.generateRrsig(invalidRrset, signatureExpiry, signatureInception);

      expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.BOGUS);
    });

    describe('Label count', () => {
      test('Count greater than actual number should be SECURE', async () => {
        const differentRrset = new RRSet([
          RECORD.shallowCopy({ name: `subdomain.${RECORD.name}` }),
        ]);
        const signer = await ZoneSigner.generate(algorithm, RECORD.name);
        const { data } = signer.generateRrsig(differentRrset, signatureExpiry, signatureInception);

        expect(data.verifyRrset(differentRrset, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Count equal to actual number should be SECURE', () => {
        const differentRrset = new RRSet([RECORD]);
        const { data } = tldSigner.generateRrsig(
          differentRrset,
          signatureExpiry,
          signatureInception,
        );

        expect(data.verifyRrset(differentRrset, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Count less than actual number should be BOGUS', async () => {
        const differentRrset = new RRSet([RECORD]);
        const { data } = tldSigner.generateRrsig(
          differentRrset,
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

        expect(mismatchingData.verifyRrset(differentRrset, now)).toEqual(SecurityStatus.BOGUS);
      });
    });

    describe('Signature validity period', () => {
      test('Expiry date equal to current time should be SECURE', () => {
        const { data } = tldSigner.generateRrsig(rrset, now, signatureInception);

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Expiry date later than current time should be SECURE', () => {
        const { data } = tldSigner.generateRrsig(rrset, addSeconds(now, 1), signatureInception);

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Expiry date earlier than current time should be BOGUS', () => {
        const { data } = tldSigner.generateRrsig(rrset, subSeconds(now, 1), signatureInception);

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.BOGUS);
      });

      test('Inception date equal to current time should be SECURE', () => {
        const { data } = tldSigner.generateRrsig(rrset, signatureExpiry, now);

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Inception date earlier than current time should be SECURE', () => {
        const { data } = tldSigner.generateRrsig(rrset, signatureExpiry, subSeconds(now, 1));

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Inception date later than current time should be BOGUS', () => {
        const { data } = tldSigner.generateRrsig(rrset, signatureExpiry, addSeconds(now, 1));

        expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.BOGUS);
      });
    });

    test('Valid RRset should be SECURE', () => {
      const { data } = tldSigner.generateRrsig(rrset, signatureExpiry, signatureInception);

      expect(data.verifyRrset(rrset, now)).toEqual(SecurityStatus.SECURE);
    });
  });
});
