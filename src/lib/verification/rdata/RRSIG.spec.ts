import { addMinutes, setMilliseconds } from 'date-fns';

import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { ZoneSigner } from '../../signing/ZoneSigner';
import { RRSIG } from './RRSIG';
import { InvalidRdataError } from '../../errors';
import { serialiseName } from '../../dns/name';
import { RRSet } from '../../dns/RRSet';
import { RECORD } from '../../../testUtils/stubs';

describe('RRSIG', () => {
  describe('deserialise', () => {
    const algorithm = DNSSECAlgorithm.RSASHA256;
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

      expect(() => RRSIG.deserialise(malformedRrsigData)).toThrowWithMessage(
        InvalidRdataError,
        'RRSIG data is malformed',
      );
    });

    test('Empty signature should be refused', () => {
      const nameSerialised = serialiseName('example.com.');
      const serialisation = Buffer.allocUnsafe(18 + nameSerialised.byteLength);
      nameSerialised.copy(serialisation, 18);

      expect(() => RRSIG.deserialise(serialisation)).toThrowWithMessage(
        InvalidRdataError,
        'Signature is empty',
      );
    });

    test('Record type should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.type).toEqual(RECORD.type);
    });

    test('Algorithm should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.algorithm).toEqual(algorithm);
    });

    test('Labels should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry);

      const rrsig = RRSIG.deserialise(serialisation.data);

      const expectedLabelCount = rrset.name.replace(/\.$/, '').split('.').length;
      expect(rrsig.labels).toEqual(expectedLabelCount);
    });

    test('TTL should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.ttl).toEqual(rrset.ttl);
    });

    test('Signature expiry date should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.signatureExpiry).toEqual(signatureExpiry);
    });

    test('Signature inception date should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.signatureInception).toEqual(signatureInception);
    });

    test('Key tag should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.keyTag).toEqual(signer.keyTag);
    });

    test('Signer name should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.signerName).toEqual(signer.zoneName);
    });

    test('Signature should be extracted', () => {
      const serialisation = signer.generateRrsig(rrset, signatureExpiry, signatureInception);

      const rrsig = RRSIG.deserialise(serialisation.data);

      expect(rrsig.signature.byteLength).toBeGreaterThan(0);
    });
  });
});
