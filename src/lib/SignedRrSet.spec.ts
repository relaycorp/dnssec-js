import type { KeyObject } from 'node:crypto';

import { jest } from '@jest/globals';
import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { QUESTION, RECORD, RECORD_TLD, RRSET } from '../testUtils/dnsStubs';
import { ZoneSigner } from '../testUtils/dnssec/ZoneSigner';

import { SignedRrSet } from './SignedRrSet';
import { DnssecAlgorithm } from './DnssecAlgorithm';
import { RrSet } from './dns/RrSet';
import type { DnskeyRecord } from './dnssecRecords';
import { DatePeriod } from './DatePeriod';
import { serialisePublicKey } from './utils/crypto/keySerialisation';
import { DnskeyData } from './rdata/DnskeyData';
import { RrsigData } from './rdata/RrsigData';
import { DnsClass } from './dns/ianaClasses';
import { IANA_RR_TYPE_IDS } from './dns/ianaRrTypes';
import { SignatureGenerationOptions } from '../testUtils/dnssec/SignatureGenerationOptions';

describe('SignedRrSet', () => {
  const NOW = setMilliseconds(new Date(), 0);
  const RRSIG_OPTIONS: SignatureGenerationOptions = {
    signatureInception: NOW,
    signatureExpiry: addSeconds(NOW, 60),
  };

  let tldSigner: ZoneSigner;
  let apexSigner: ZoneSigner;

  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);
    apexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD.name);
  });

  describe('initFromRecords', () => {
    const STUB_KEY_TAG = 12_345;

    test('Empty RRSIGs should be allowed', () => {
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG for different owner should be ignored', () => {
      const differentRecord = RECORD.shallowCopy({ name: `sub.${RECORD.name}` });
      const differentRrsig = apexSigner.generateRrsig(
        RrSet.init(QUESTION.shallowCopy({ name: differentRecord.name }), [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_OPTIONS,
      );

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG for different class should be ignored', () => {
      const rrsig = apexSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);
      const differentRrsigRecord = rrsig.record.shallowCopy({ class: DnsClass.CH });
      expect(differentRrsigRecord.classId).not.toStrictEqual(rrsig.record.classId);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, differentRrsigRecord]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG with mismatching type field should be accepted', () => {
      const differentRecord = RECORD.shallowCopy({ type: IANA_RR_TYPE_IDS.A });
      expect(differentRecord.typeId).not.toStrictEqual(RECORD.typeId);
      const differentRrsig = apexSigner.generateRrsig(
        RrSet.init(QUESTION.shallowCopy({ type: differentRecord.typeId }), [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_OPTIONS,
      );

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([
        differentRrsig.record,
      ]);
    });

    test('RRSIG with mismatching TTL should be accepted', () => {
      const differentRecord = RECORD.shallowCopy({ ttl: RECORD.ttl + 1 });
      const differentRrsig = apexSigner.generateRrsig(
        RrSet.init(QUESTION, [differentRecord]),
        STUB_KEY_TAG,
        RRSIG_OPTIONS,
      );

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([
        differentRrsig.record,
      ]);
    });

    test('RRSIG with signer name outside tree should be ignored', async () => {
      const differentApexSigner = await ZoneSigner.generate(
        apexSigner.algorithm,
        `not-${apexSigner.zoneName}`,
      );
      const invalidRrsig = differentApexSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);
      expect(invalidRrsig.data.signerName).toStrictEqual(differentApexSigner.zoneName);
      const validRrsig = apexSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [
        RECORD,
        validRrsig.record,
        invalidRrsig.record,
      ]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([validRrsig.record]);
    });

    test('RRSIG with signer name under RRset name should be ignored', async () => {
      const subdomainSigner = await ZoneSigner.generate(
        apexSigner.algorithm,
        `subdomain.${apexSigner.zoneName}`,
      );
      const invalidRrsig = subdomainSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);
      expect(invalidRrsig.data.signerName).toStrictEqual(subdomainSigner.zoneName);
      const validRrsig = apexSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [
        RECORD,
        validRrsig.record,
        invalidRrsig.record,
      ]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([validRrsig.record]);
    });

    test('RRSIG with signer name equal to RRset name should be allowed', () => {
      const rrsig = apexSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);
      expect(rrsig.data.signerName).toStrictEqual(RRSET.name);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, rrsig.record]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([rrsig.record]);
    });

    test('RRSIG with signer name above RRset name should be allowed', () => {
      const rrsig = tldSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);
      expect(rrsig.data.signerName).toStrictEqual(tldSigner.zoneName);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, rrsig.record]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([rrsig.record]);
    });

    test('Valid records should be split into RRSet and RRSig', () => {
      const rrsig = apexSigner.generateRrsig(RRSET, STUB_KEY_TAG, RRSIG_OPTIONS);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, rrsig.record]);

      expect(signedRrset.rrset).toStrictEqual(RRSET);
      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([rrsig.record]);
    });
  });

  describe('signerNames', () => {
    test('Nothing should be output if there are no RRSigs', () => {
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD]);

      expect(signedRrset.signerNames).toBeEmpty();
    });

    test('A single name should be output if there is only one RRSig', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.signerNames).toStrictEqual([apexSigner.zoneName]);
    });

    test('Multiple names should be output if there are multiple RRSigs', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig1 = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const rrsig2 = tldSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [
        ...RRSET.records,
        rrsig1.record,
        rrsig2.record,
      ]);

      expect(signedRrset.signerNames).toContainAllValues([apexSigner.zoneName, tldSigner.zoneName]);
    });

    test('Names should be sorted from longest to shortest', () => {
      const dnskey = apexSigner.generateDnskey();
      const apexRrsig = apexSigner.generateRrsig(
        RRSET,
        dnskey.data.calculateKeyTag(),
        RRSIG_OPTIONS,
      );
      const tldRrsig = tldSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [
        ...RRSET.records,
        tldRrsig.record,
        apexRrsig.record,
      ]);

      expect(signedRrset.signerNames).toStrictEqual([apexSigner.zoneName, tldSigner.zoneName]);
    });

    test('Names should be deduped', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [
        ...RRSET.records,
        rrsig.record,
        rrsig.record, // Duplicate
      ]);

      expect(signedRrset.rrsigs).toHaveLength(2);
      expect(signedRrset.signerNames).toStrictEqual([apexSigner.zoneName]);
    });
  });

  describe('verify', () => {
    const VALIDITY_PERIOD = DatePeriod.init(
      RRSIG_OPTIONS.signatureInception,
      RRSIG_OPTIONS.signatureExpiry,
    );

    test('Verification should fail if no RRSig is deemed valid by any DNSKEY', () => {
      const dnskey1 = apexSigner.generateDnskey({ flags: { secureEntryPoint: true } });
      const dnskey2 = apexSigner.generateDnskey({ flags: { secureEntryPoint: false } });
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey1.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey2], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig signer does not match DNSKEY RR owner', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
      const invalidDnskey: DnskeyRecord = {
        data: dnskey.data,
        record: dnskey.record.shallowCopy({ name: `not-${dnskey.record.name}` }),
      };

      expect(signedRrset.verify([invalidDnskey], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig signer does not match explicit one', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD, `not-${QUESTION.name}`)).toBeFalse();
    });

    test('Verification should fail if not deemed valid by any RRSig', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const type = IANA_RR_TYPE_IDS.A;
      expect(type).not.toStrictEqual(RRSET.type); // Make sure we're picking something different
      const invalidRecords = RRSET.records.map((record) => record.shallowCopy({ type }));
      const signedRrset = SignedRrSet.initFromRecords(QUESTION.shallowCopy({ type }), [
        ...invalidRecords,
        rrsig.record,
      ]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD)).toBeFalse();
    });

    test('Verification should fail if RRSig expired', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
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
        const validDnskey = apexSigner.generateDnskey();
        const dnssecAlgorithm = apexSigner.algorithm;
        const invalidSigner = await ZoneSigner.generate(dnssecAlgorithm, apexSigner.zoneName);
        const invalidDnskey = invalidSigner.generateDnskey();
        const rrsig = apexSigner.generateRrsig(
          RRSET,
          validDnskey.data.calculateKeyTag(),
          RRSIG_OPTIONS,
        );
        const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

        expect(signedRrset.verify([invalidDnskey, validDnskey], VALIDITY_PERIOD)).toBeTrue();

        expect(verifyRrsetSpy).toHaveBeenNthCalledWith(
          1,
          expect.anything(),
          expect.toSatisfy<KeyObject>((key) =>
            serialisePublicKey(invalidDnskey.data.publicKey, dnssecAlgorithm).equals(
              serialisePublicKey(key, dnssecAlgorithm),
            ),
          ),
        );
        expect(verifyRrsetSpy).toHaveBeenNthCalledWith(
          2,
          expect.anything(),
          expect.toSatisfy<KeyObject>((key) =>
            serialisePublicKey(validDnskey.data.publicKey, dnssecAlgorithm).equals(
              serialisePublicKey(key, dnssecAlgorithm),
            ),
          ),
        );
      } finally {
        verifyRrsigSpy.mockRestore();
        verifyRrsetSpy.mockRestore();
      }
    });

    test('Verification should succeed if deemed valid by a valid RRSig', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey], VALIDITY_PERIOD)).toBeTrue();
    });
  });
});
