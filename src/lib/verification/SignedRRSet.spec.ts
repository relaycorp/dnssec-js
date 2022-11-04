import { addMinutes, setMilliseconds } from 'date-fns';

import { SignedRRSet } from './SignedRRSet';
import { DnssecValidationError } from '../errors';
import { RECORD, RECORD_TLD } from '../../testUtils/stubs';
import { ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { RRSet } from '../dns/RRSet';

describe('SignedRRSet', () => {
  let signer: ZoneSigner;
  beforeAll(async () => {
    signer = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);
  });

  describe('initFromRecords', () => {
    const STUB_KEY_TAG = 12345;
    const RRSIG_EXPIRY = addMinutes(setMilliseconds(new Date(), 0), 1);

    test('Empty RRSIGs should be allowed', () => {
      const signedRrset = SignedRRSet.initFromRecords([RECORD]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('Malformed RRSig should be refused', () => {
      const rrset = new RRSet([RECORD]);
      const rrsig = signer.generateRrsig(rrset, STUB_KEY_TAG, RRSIG_EXPIRY);
      const malformedRrsigRecord = rrsig.record.shallowCopy({ dataSerialised: Buffer.alloc(2) });

      expect(() => SignedRRSet.initFromRecords([RECORD, malformedRrsigRecord])).toThrowWithMessage(
        DnssecValidationError,
        `RRSig data for ${malformedRrsigRecord.name}/${malformedRrsigRecord.type} is malformed`,
      );
    });

    test('RRSIG for different owner should be ignored', async () => {
      const differentRecord = RECORD.shallowCopy({ name: `not-${RECORD.name}` });
      const differentRrsig = signer.generateRrsig(
        new RRSet([differentRecord]),
        STUB_KEY_TAG,
        RRSIG_EXPIRY,
      );

      const signedRrset = SignedRRSet.initFromRecords([RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG for different class should be ignored', async () => {
      const rrsig = signer.generateRrsig(new RRSet([RECORD]), STUB_KEY_TAG, RRSIG_EXPIRY);
      const differentRrsigRecord = rrsig.record.shallowCopy({ class: 'foobar' as any });

      const signedRrset = SignedRRSet.initFromRecords([RECORD, differentRrsigRecord]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG with mismatching type field should be accepted', async () => {
      const differentRecord = RECORD.shallowCopy({ type: RECORD.type + 1 });
      const differentRrsig = signer.generateRrsig(
        new RRSet([differentRecord]),
        STUB_KEY_TAG,
        RRSIG_EXPIRY,
      );

      const signedRrset = SignedRRSet.initFromRecords([RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toEqual([differentRrsig]);
    });

    test('RRSIG with mismatching TTL should be accepted', async () => {
      const differentRecord = RECORD.shallowCopy({ ttl: RECORD.ttl + 1 });
      const differentRrsig = signer.generateRrsig(
        new RRSet([differentRecord]),
        STUB_KEY_TAG,
        RRSIG_EXPIRY,
      );

      const signedRrset = SignedRRSet.initFromRecords([RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toEqual([differentRrsig]);
    });

    test('Valid records should be split into RRSet and RRSig', () => {
      const rrset = new RRSet([RECORD]);
      const rrsig = signer.generateRrsig(rrset, STUB_KEY_TAG, RRSIG_EXPIRY);

      const signedRrset = SignedRRSet.initFromRecords([RECORD, rrsig.record]);

      expect(signedRrset.rrset).toEqual(rrset);
      expect(signedRrset.rrsigs).toEqual([rrsig]);
    });
  });
});
