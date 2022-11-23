import { jest } from '@jest/globals';
import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { SignedRRSet } from './SignedRRSet';
import { QUESTION, RECORD, RRSET } from '../../testUtils/dnsStubs';
import { SignatureGenerationOptions, ZoneSigner } from '../../testUtils/dnssec/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { RRSet } from '../dns/RRSet';
import { DnskeyRecord } from '../dnssecRecords';
import { DatePeriod } from './DatePeriod';
import { serialisePublicKey } from '../utils/crypto/keySerialisation';
import { DnskeyData } from '../rdata/DnskeyData';
import { RrsigData } from '../rdata/RrsigData';
import { DnsClass } from '../dns/ianaClasses';
import { IANA_RR_TYPE_IDS } from '../dns/ianaRrTypes';

describe('SignedRRSet', () => {
  const RRSIG_OPTIONS: Partial<SignatureGenerationOptions> = {
    signatureExpiry: addSeconds(setMilliseconds(new Date(), 0), 60),
  };

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

    test('RRSIG for different owner should be ignored', async () => {
      const differentRecord = RECORD.shallowCopy({ name: `sub.${RECORD.name}` });
      const differentRrsig = signer.generateRrsig(
        RRSet.init(QUESTION.shallowCopy({ name: differentRecord.name }), [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_OPTIONS,
      );

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG for different class should be ignored', async () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);
      const differentRrsigRecord = rrsig.record.shallowCopy({ class: DnsClass.CH });
      expect(differentRrsigRecord.class_).not.toEqual(rrsig.record.class_);

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsigRecord]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG with mismatching type field should be accepted', async () => {
      const differentRecord = RECORD.shallowCopy({ type: IANA_RR_TYPE_IDS.A });
      expect(differentRecord.typeId).not.toEqual(RECORD.typeId);
      const differentRrsig = signer.generateRrsig(
        RRSet.init(QUESTION.shallowCopy({ type: differentRecord.typeId }), [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_OPTIONS,
      );

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs.map((r) => r.record)).toEqual([differentRrsig.record]);
    });

    test('RRSIG with mismatching TTL should be accepted', async () => {
      const differentRecord = RECORD.shallowCopy({ ttl: RECORD.ttl + 1 });
      const differentRrsig = signer.generateRrsig(
        RRSet.init(QUESTION, [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_OPTIONS,
      );

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs.map((r) => r.record)).toEqual([differentRrsig.record]);
    });

    test('Valid records should be split into RRSet and RRSig', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);

      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [RECORD, rrsig.record]);

      expect(signedRrset.rrset).toEqual(RRSET);
      expect(signedRrset.rrsigs.map((r) => r.record)).toEqual([rrsig.record]);
    });
  });

  describe('verify', () => {
    const VALIDITY_PERIOD = DatePeriod.init(
      subSeconds(RRSIG_OPTIONS.signatureExpiry!, 1),
      RRSIG_OPTIONS.signatureExpiry!,
    );

    test('Verification should fail if no RRSig is deemed valid by any DNSKEY', () => {
      const dnskey1 = signer.generateDnskey({ flags: { secureEntryPoint: true } });
      const dnskey2 = signer.generateDnskey({ flags: { secureEntryPoint: false } });
      const rrsig = signer.generateRrsig(RRSET, dnskey1.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey2], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig signer does not match DNSKEY RR owner', async () => {
      const dnskey = signer.generateDnskey();
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
      const invalidDnskey: DnskeyRecord = {
        data: dnskey.data,
        record: dnskey.record.shallowCopy({ name: `not-${dnskey.record.name}` }),
      };

      expect(signedRrset.verify([invalidDnskey], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig signer does not match explicit one', () => {
      const dnskey = signer.generateDnskey();
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD, `not-${QUESTION.name}`)).toBeFalse();
    });

    test('Verification should fail if not deemed valid by any RRSig', () => {
      const dnskey = signer.generateDnskey();
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const type = IANA_RR_TYPE_IDS.A;
      expect(type).not.toEqual(RRSET.type); // Make sure we're picking something different indeed
      const invalidRecords = RRSET.records.map((r) => r.shallowCopy({ type }));
      const signedRrset = SignedRRSet.initFromRecords(QUESTION.shallowCopy({ type }), [
        ...invalidRecords,
        rrsig.record,
      ]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig expired', () => {
      const dnskey = signer.generateDnskey();
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
      const invalidPeriod = DatePeriod.init(
        subSeconds(rrsig.data.signatureInception, 2),
        subSeconds(rrsig.data.signatureInception, 1),
      );

      expect(signedRrset.verify([dnskey], invalidPeriod)).toBeFalse();
    });

    test('RRSig should be verified with the correct DNSKEY public key', async () => {
      // Simulate two DNSKEYs with the same key tag but different public keys
      const verifyRrsigSpy = jest.spyOn(DnskeyData.prototype, 'verifyRrsig');
      const verifyRrsetSpy = jest.spyOn(RrsigData.prototype, 'verifyRrset');
      try {
        verifyRrsigSpy.mockReturnValue(true);
        const validDnskey = signer.generateDnskey();
        const dnssecAlgorithm = signer.algorithm;
        const invalidSigner = await ZoneSigner.generate(dnssecAlgorithm, signer.zoneName);
        const invalidDnskey = invalidSigner.generateDnskey();
        const rrsig = signer.generateRrsig(
          RRSET,
          validDnskey.data.calculateKeyTag(),
          RRSIG_OPTIONS,
        );
        const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

        expect(signedRrset.verify([invalidDnskey, validDnskey], VALIDITY_PERIOD)).toBeTrue();

        expect(verifyRrsetSpy).toHaveBeenNthCalledWith(
          1,
          expect.anything(),
          expect.toSatisfy((k) =>
            serialisePublicKey(invalidDnskey.data.publicKey, dnssecAlgorithm).equals(
              serialisePublicKey(k, dnssecAlgorithm),
            ),
          ),
        );
        expect(verifyRrsetSpy).toHaveBeenNthCalledWith(
          2,
          expect.anything(),
          expect.toSatisfy((k) =>
            serialisePublicKey(validDnskey.data.publicKey, dnssecAlgorithm).equals(
              serialisePublicKey(k, dnssecAlgorithm),
            ),
          ),
        );
      } finally {
        verifyRrsigSpy.mockRestore();
        verifyRrsetSpy.mockRestore();
      }
    });

    test('Verification should succeed if deemed valid by a valid RRSig', () => {
      const dnskey = signer.generateDnskey();
      const rrsig = signer.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRRSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD)).toBeTrue();
    });
  });
});
