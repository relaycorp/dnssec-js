import type { KeyObject } from 'node:crypto';

import { jest } from '@jest/globals';
import { addSeconds, differenceInSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { QUESTION, RECORD, RECORD_TLD, RRSET } from '../testUtils/dnsStubs.js';

import { type DnskeyGenerationOptions, ZoneSigner } from './testing/ZoneSigner.js';
import type { SignatureOptions } from './testing/SignatureOptions.js';
import { SignedRrSet } from './SignedRrSet.js';
import { DnssecAlgorithm } from './DnssecAlgorithm.js';
import { RrSet } from './utils/dns/RrSet.js';
import type { DnskeyRecord } from './records/dnssecRecords.js';
import { DatePeriod } from './DatePeriod.js';
import { serialisePublicKey } from './utils/crypto/keySerialisation.js';
import { DnskeyData } from './records/DnskeyData.js';
import { RrsigData } from './records/RrsigData.js';
import { DnsClass } from './utils/dns/ianaClasses.js';
import { IANA_RR_TYPE_IDS } from './utils/dns/ianaRrTypes.js';
import { type DatedValue } from './DatedValue.js';

const NOW = setMilliseconds(new Date(), 0);
const RRSIG_OPTIONS: SignatureOptions = {
  signatureInception: NOW,
  signatureExpiry: addSeconds(NOW, 60),
};

describe('SignedRrSet', () => {
  let tldSigner: ZoneSigner;
  let apexSigner: ZoneSigner;

  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);
    apexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD.name);
  });

  describe('initFromRecords', () => {
    const stubKeytag = 12_345;

    test('Empty RRSIGs should be allowed', () => {
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG for different owner should be ignored', () => {
      const differentRecord = RECORD.shallowCopy({ name: `sub.${RECORD.name}` });
      const differentRrsig = apexSigner.generateRrsig(
        RrSet.init(QUESTION.shallowCopy({ name: differentRecord.name }), [differentRecord]),
        stubKeytag,
        RRSIG_OPTIONS,
      );

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, differentRrsig.record]);

      expect(signedRrset.rrsigs).toBeEmpty();
    });

    test('RRSIG for different class should be ignored', () => {
      const rrsig = apexSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);
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
        stubKeytag,
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
        stubKeytag,
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
      const invalidRrsig = differentApexSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);
      expect(invalidRrsig.data.signerName).toStrictEqual(differentApexSigner.zoneName);
      const validRrsig = apexSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);

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
      const invalidRrsig = subdomainSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);
      expect(invalidRrsig.data.signerName).toStrictEqual(subdomainSigner.zoneName);
      const validRrsig = apexSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [
        RECORD,
        validRrsig.record,
        invalidRrsig.record,
      ]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([validRrsig.record]);
    });

    test('RRSIG with signer name equal to RRset name should be allowed', () => {
      const rrsig = apexSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);
      expect(rrsig.data.signerName).toStrictEqual(RRSET.name);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, rrsig.record]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([rrsig.record]);
    });

    test('RRSIG with signer name above RRset name should be allowed', () => {
      const rrsig = tldSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);
      expect(rrsig.data.signerName).toStrictEqual(tldSigner.zoneName);

      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [RECORD, rrsig.record]);

      expect(signedRrset.rrsigs.map((record) => record.record)).toStrictEqual([rrsig.record]);
    });

    test('Valid records should be split into RRSet and RRSig', () => {
      const rrsig = apexSigner.generateRrsig(RRSET, stubKeytag, RRSIG_OPTIONS);

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
    const validityPeriod = DatePeriod.init(
      RRSIG_OPTIONS.signatureInception,
      RRSIG_OPTIONS.signatureExpiry,
    );

    function generateDatedDnskey(
      signer: ZoneSigner,
      datePeriod: DatePeriod,
      options: Partial<DnskeyGenerationOptions> = {},
    ): DatedValue<DnskeyRecord> {
      const dnskey = signer.generateDnskey(options);
      return { value: dnskey, datePeriods: [datePeriod] };
    }

    test('Verification should fail if no RRSig is deemed valid by any DNSKEY', () => {
      const dnskey1 = apexSigner.generateDnskey({ flags: { secureEntryPoint: true } });
      const dnskey2Dated = generateDatedDnskey(apexSigner, validityPeriod, {
        flags: { secureEntryPoint: false },
      });
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey1.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([dnskey2Dated])).toBeEmpty();
    });

    test('Verification should fail if RRSig signer does not match DNSKEY RR owner', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
      const invalidDnskey: DnskeyRecord = {
        data: dnskey.data,
        record: dnskey.record.shallowCopy({ name: `not-${dnskey.record.name}` }),
      };
      const invalidDnskeyDated = { value: invalidDnskey, datePeriods: [validityPeriod] };

      expect(signedRrset.verify([invalidDnskeyDated])).toBeEmpty();
    });

    test('Verification should fail if RRSig signer does not match explicit one', () => {
      const datedDnskey = generateDatedDnskey(apexSigner, validityPeriod);
      const rrsig = apexSigner.generateRrsig(
        RRSET,
        datedDnskey.value.data.calculateKeyTag(),
        RRSIG_OPTIONS,
      );
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([datedDnskey], `not-${QUESTION.name}`)).toBeEmpty();
    });

    test('Verification should fail if not deemed valid by any RRSig', () => {
      const datedDnskey = generateDatedDnskey(apexSigner, validityPeriod);
      const rrsig = apexSigner.generateRrsig(
        RRSET,
        datedDnskey.value.data.calculateKeyTag(),
        RRSIG_OPTIONS,
      );
      const type = IANA_RR_TYPE_IDS.A;
      expect(type).not.toStrictEqual(RRSET.type); // Make sure we're picking something different
      const invalidRecords = RRSET.records.map((record) => record.shallowCopy({ type }));
      const signedRrset = SignedRrSet.initFromRecords(QUESTION.shallowCopy({ type }), [
        ...invalidRecords,
        rrsig.record,
      ]);

      expect(signedRrset.verify([datedDnskey])).toBeEmpty();
    });

    test('Verification should fail if RRSig expired', () => {
      const datedDnskey = generateDatedDnskey(apexSigner, validityPeriod);
      const rrsig = apexSigner.generateRrsig(RRSET, datedDnskey.value.data.calculateKeyTag(), {
        signatureInception: subSeconds(validityPeriod.start, 2),
        signatureExpiry: subSeconds(validityPeriod.start, 1),
      });
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([datedDnskey])).toBeEmpty();
    });

    test('RRSig should be verified with the correct DNSKEY public key', async () => {
      // Simulate two DNSKEYs with the same key tag but different public keys
      const verifyRrsigSpy = jest.spyOn(DnskeyData.prototype, 'verifyRrsig');
      const verifyRrsetSpy = jest.spyOn(RrsigData.prototype, 'verifyRrset');
      try {
        verifyRrsigSpy.mockReturnValue(true);
        const validDnskeyDated = generateDatedDnskey(apexSigner, validityPeriod);
        const dnssecAlgorithm = apexSigner.algorithm;
        const invalidSigner = await ZoneSigner.generate(dnssecAlgorithm, apexSigner.zoneName);
        const invalidDnskey = generateDatedDnskey(invalidSigner, validityPeriod);
        const rrsig = apexSigner.generateRrsig(
          RRSET,
          validDnskeyDated.value.data.calculateKeyTag(),
          RRSIG_OPTIONS,
        );
        const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

        expect(signedRrset.verify([invalidDnskey, validDnskeyDated])).toHaveLength(1);

        expect(verifyRrsetSpy).toHaveBeenNthCalledWith(
          1,
          expect.anything(),
          expect.toSatisfy<KeyObject>((key) =>
            serialisePublicKey(invalidDnskey.value.data.publicKey, dnssecAlgorithm).equals(
              serialisePublicKey(key, dnssecAlgorithm),
            ),
          ),
        );
        expect(verifyRrsetSpy).toHaveBeenNthCalledWith(
          2,
          expect.anything(),
          expect.toSatisfy<KeyObject>((key) =>
            serialisePublicKey(validDnskeyDated.value.data.publicKey, dnssecAlgorithm).equals(
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
      const datedDnskey = generateDatedDnskey(apexSigner, validityPeriod);
      const rrsig = apexSigner.generateRrsig(
        RRSET,
        datedDnskey.value.data.calculateKeyTag(),
        RRSIG_OPTIONS,
      );
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      expect(signedRrset.verify([datedDnskey])).toHaveLength(1);
    });

    test('Validity period should be intersection of RRSig and DNSKEY', () => {
      const dnskeyPeriod = DatePeriod.init(
        addSeconds(validityPeriod.start, 1),
        subSeconds(validityPeriod.end, 1),
      );
      const datedDnskey = generateDatedDnskey(apexSigner, dnskeyPeriod);
      const rrsigExpiry = subSeconds(dnskeyPeriod.end, 1);
      const rrsig = apexSigner.generateRrsig(RRSET, datedDnskey.value.data.calculateKeyTag(), {
        ...RRSIG_OPTIONS,
        signatureExpiry: rrsigExpiry,
      });
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);

      const [period] = signedRrset.verify([datedDnskey]);

      expect(period.start).toStrictEqual(dnskeyPeriod.start);
      expect(period.end).toStrictEqual(rrsigExpiry);
    });

    test('Non-matching DNSSKEY periods should be ignored', () => {
      const dnskey = apexSigner.generateDnskey();
      const rrsig = apexSigner.generateRrsig(RRSET, dnskey.data.calculateKeyTag(), RRSIG_OPTIONS);
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [...RRSET.records, rrsig.record]);
      const invalidPeriod = DatePeriod.init(
        addSeconds(validityPeriod.end, 1),
        addSeconds(validityPeriod.end, 2),
      );
      const datedDnskey = { value: dnskey, datePeriods: [validityPeriod, invalidPeriod] };

      const periods = signedRrset.verify([datedDnskey]);

      expect(periods).toHaveLength(1);
      const [period] = periods;
      expect(period.start).toStrictEqual(validityPeriod.start);
      expect(period.end).toStrictEqual(validityPeriod.end);
    });

    test('Multiple periods should be returned if multiple signatures match', () => {
      const datedDnskey = generateDatedDnskey(apexSigner, validityPeriod);
      const cutoffDate = addSeconds(
        validityPeriod.start,
        differenceInSeconds(validityPeriod.end, validityPeriod.start),
      );
      const { record: rrsig1Record } = apexSigner.generateRrsig(
        RRSET,
        datedDnskey.value.data.calculateKeyTag(),
        { ...RRSIG_OPTIONS, signatureExpiry: cutoffDate },
      );
      const { record: rrsig2Record } = apexSigner.generateRrsig(
        RRSET,
        datedDnskey.value.data.calculateKeyTag(),
        { ...RRSIG_OPTIONS, signatureInception: cutoffDate },
      );
      const signedRrset = SignedRrSet.initFromRecords(QUESTION, [
        ...RRSET.records,
        rrsig1Record,
        rrsig2Record,
      ]);

      const periods = signedRrset.verify([datedDnskey]);

      expect(periods).toHaveLength(2);
      const [period1, period2] = periods;
      expect(period1.start).toStrictEqual(validityPeriod.start);
      expect(period1.end).toStrictEqual(cutoffDate);
      expect(period2.start).toStrictEqual(cutoffDate);
      expect(period2.end).toStrictEqual(validityPeriod.end);
    });
  });
});
