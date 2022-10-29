import { addMinutes, setMilliseconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { ZoneSigner } from '../signing/ZoneSigner';
import { RrsigData } from './RrsigData';
import { InvalidRdataError } from '../errors';
import { serialiseName } from '../dns/name';
import { RRSet } from '../dns/RRSet';
import { RECORD } from '../../testUtils/stubs';

describe('RrsigData', () => {
  describe('deserialise', () => {
    const algorithm = DnssecAlgorithm.RSASHA256;
    const rrset = new RRSet([RECORD]);
    const signatureInception = setMilliseconds(new Date(), 0);
    const signatureExpiry = addMinutes(signatureInception, 10);

    let signer: ZoneSigner;
    beforeAll(async () => {
      signer = await ZoneSigner.generate(algorithm, 'com.');
    });

    test('Malformed value should be refused', () => {
      // 18 octets means that the Signer's Name and Signature are missing
      const malformedRrsigData = Buffer.allocUnsafe(18);

      expect(() => RrsigData.deserialise(malformedRrsigData)).toThrowWithMessage(
        InvalidRdataError,
        'RRSIG data is malformed',
      );
    });

    test('Empty signature should be refused', () => {
      const nameSerialised = serialiseName('example.com.');
      const serialisation = Buffer.allocUnsafe(18 + nameSerialised.byteLength);
      nameSerialised.copy(serialisation, 18);

      expect(() => RrsigData.deserialise(serialisation)).toThrowWithMessage(
        InvalidRdataError,
        'Signature is empty',
      );
    });

    test('Record type should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.type).toEqual(RECORD.type);
    });

    test('Algorithm should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.algorithm).toEqual(algorithm);
    });

    test('Labels should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      const expectedLabelCount = rrset.name.replace(/\.$/, '').split('.').length;
      expect(rrsigData.labels).toEqual(expectedLabelCount);
    });

    test('TTL should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.ttl).toEqual(rrset.ttl);
    });

    test('Signature expiry date should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureExpiry).toEqual(signatureExpiry);
    });

    test('Signature inception date should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signatureInception).toEqual(signatureInception);
    });

    test('Key tag should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.keyTag).toEqual(signer.keyTag);
    });

    test('Signer name should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signerName).toEqual(signer.zoneName);
    });

    test('Signature should be extracted', () => {
      const rrsig = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsigData = RrsigData.deserialise(rrsig.record.dataSerialised);

      expect(rrsigData.signature.byteLength).toBeGreaterThan(0);
    });
  });
});
