import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { SignedRRSet } from './SignedRRSet';
import { QUESTION, RECORD, RRSET } from '../../testUtils/dnsStubs';
import { ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { RRSet } from '../dns/RRSet';
import { DnskeyRecord } from '../dnssecRecords';
import { DatePeriod } from './DatePeriod';

describe('SignedRRSet', () => {
  const RRSIG_EXPIRY = addSeconds(setMilliseconds(new Date(), 0), 60);

  let signer: ZoneSigner;
  beforeAll(async () => {
    signer = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD.name);
  });

  describe('initFromRecords', () => {
    const STUB_KEY_TAG = 12345;

    test('Empty RRSIGs should be allowed', () => {
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('Malformed RRSig should be ignored', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_EXPIRY);
      const malformedRrsigRecord = rrsig.record.shallowCopy({ dataSerialised: Buffer.alloc(2) });

      const signedRRSet = SignedRRSet.initFromRecords(QUESTION, [RECORD, malformedRrsigRecord]);
      expect(signedRRSet.rrsigs).toBeEmpty();
    });

    test('RRSIG for different owner should be ignored', async () => {
      const differentRecord = RECORD.shallowCopy({ name: `sub.${RECORD.name}` });
      const differentRrsig = signer.generateRrsig(
        RRSet.init({ ...QUESTION, name: differentRecord.name }, [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_EXPIRY,
      );

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG for different class should be ignored', async () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_EXPIRY);
      const differentRrsigRecord = rrsig.record.shallowCopy({ class: 'foobar' as any });

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsigRecord]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG with mismatching type field should be accepted', async () => {
      const differentRecord = RECORD.shallowCopy({ type: RECORD.type + 1 });
      const differentRrsig = signer.generateRrsig(
        RRSet.init({ ...QUESTION, type: differentRecord.type }, [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_EXPIRY,
      );

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toEqual([differentRrsig]);
    });

    test('RRSIG with mismatching TTL should be accepted', async () => {
      const differentRecord = RECORD.shallowCopy({ ttl: RECORD.ttl + 1 });
      const differentRrsig = signer.generateRrsig(
        RRSet.init(QUESTION, [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_EXPIRY,
      );

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toEqual([differentRrsig]);
    });

    test('Valid records should be split into RRSet and RRSig', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_EXPIRY);

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, rrsig.record]);

      expect(signedRrset.rrset).toEqual(RRSET);
      expect(signedRrset.rrsigs).toEqual([rrsig]);
    });
  });

  describe('verify', () => {
    const VALIDITY_PERIOD = DatePeriod.init(subSeconds(RRSIG_EXPIRY, 1), RRSIG_EXPIRY);

    test('Verification should fail if no RRSig is deemed valid by any DNSKEY', () => {
      const dnskey1 = signer.generateDnskey(42, { secureEntryPoint: true });
      const dnskey2 = signer.generateDnskey(42, { secureEntryPoint: false });
      const rrsig = signer.generateRrsig(RRSET, dnskey1.data.calculateKeyTag(), RRSIG_EXPIRY);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey2], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig signer does not match DNSKEY RR owner', async () => {
      const dnskey = signer.generateDnskey(42);
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_EXPIRY);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
      const invalidDnskey: DnskeyRecord = {
        data: dnskey.data,
        record: dnskey.record.shallowCopy({ name: `not-${dnskey.record.name}` }),
      };

      expect(signedRrset.verify([invalidDnskey], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig signer does not match explicit one', () => {
      const dnskey = signer.generateDnskey(42);
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_EXPIRY);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD, `not-${QUESTION.name}`)).toBeFalse();
    });

    test('Verification should fail if not deemed valid by any RRSig', () => {
      const dnskey = signer.generateDnskey(42);
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_EXPIRY);
      const invalidRecords = RRSET.records.map((r) => r.shallowCopy({ ttl: r.ttl + 1 }));
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...invalidRecords, rrsig.record]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig expired', () => {
      const dnskey = signer.generateDnskey(42);
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_EXPIRY);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
      const invalidPeriod = DatePeriod.init(
        subSeconds(rrsig.data.signatureInception, 2),
        subSeconds(rrsig.data.signatureInception, 1),
      );

      expect(signedRrset.verify([dnskey], invalidPeriod)).toBeFalse();
    });

    test('Verification should succeed if deemed valid by a valid RRSig', () => {
      const dnskey = signer.generateDnskey(42);
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_EXPIRY);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD)).toBeTrue();
    });
  });
});
