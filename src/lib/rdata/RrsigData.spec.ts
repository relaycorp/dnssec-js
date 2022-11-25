import { addMinutes, setMilliseconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import type { SignatureGenerationOptions } from '../../testUtils/dnssec/ZoneSigner';
import { ZoneSigner } from '../../testUtils/dnssec/ZoneSigner';
import { RRSet } from '../dns/RRSet';
import { QUESTION, RECORD, RRSET } from '../../testUtils/dnsStubs';
import { IANA_RR_TYPE_IDS } from '../dns/ianaRrTypes';

import { RrsigData } from './RrsigData';

describe('RrsigData', () => {
  const STUB_KEY_TAG = 12_345;

  const NOW = setMilliseconds(new Date(), 0);
  const SIGNATURE_OPTIONS: SignatureGenerationOptions = {
    signatureExpiry: addMinutes(NOW, 10),
    signatureInception: NOW,
  };

  let signer: ZoneSigner;

  beforeAll(async () => {
    signer = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD.name);
  });

  describe('constructor', () => {
    test('Signer name should be normalised if necessary', () => {
      const signerName = 'example.com';
      const data = new RrsigData(
        RRSET.type,
        signer.algorithm,
        3,
        RRSET.ttl,
        SIGNATURE_OPTIONS.signatureExpiry,
        SIGNATURE_OPTIONS.signatureInception,
        42,
        signerName,
        Buffer.from([]),
      );

      expect(data.signerName).toBe(`${signerName}.`);
    });
  });

  describe('initFromPacket', () => {
    test('Record type should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.type).toEqual(RECORD.typeId);
    });

    test('Algorithm should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.algorithm).toEqual(signer.algorithm);
    });

    test('Labels should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      const expectedLabelCount = RRSET.name.replace(/\.$/u, '').split('.').length;
      expect(rrsigData.labels).toEqual(expectedLabelCount);
    });

    test('TTL should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.ttl).toEqual(RRSET.ttl);
    });

    test('Signature expiry date should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.signatureExpiry).toEqual(SIGNATURE_OPTIONS.signatureExpiry);
    });

    test('Signature inception date should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.signatureInception).toEqual(SIGNATURE_OPTIONS.signatureInception);
    });

    test('Key tag should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.keyTag).toEqual(STUB_KEY_TAG);
    });

    test('Signer name should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.signerName).toEqual(signer.zoneName);
    });

    test('Signature should be extracted', () => {
      const rrsig = signer.generateRrsig(RRSET, STUB_KEY_TAG, SIGNATURE_OPTIONS);

      const rrsigData = RrsigData.initFromPacket(rrsig.record.dataFields);

      expect(rrsigData.signature).toEqual(rrsig.data.signature);
    });
  });

  describe('verifyRrset', () => {
    test('Covered type should match RRset type', () => {
      const type = IANA_RR_TYPE_IDS.A;
      expect(type).not.toEqual(RECORD.typeId);
      const invalidRrset = RRSet.init(QUESTION.shallowCopy({ type }), [
        RECORD.shallowCopy({ type }),
      ]);
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
