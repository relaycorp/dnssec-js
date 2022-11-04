import { addMinutes, addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { ZoneSigner } from '../signing/ZoneSigner';
import { DnskeyData } from './DnskeyData';
import { InvalidRdataError } from '../errors';
import { RECORD, RECORD_TLD } from '../../testUtils/stubs';
import { SecurityStatus } from '../verification/SecurityStatus';
import { RRSet } from '../dns/RRSet';

describe('DnskeyData', () => {
  const algorithm = DnssecAlgorithm.RSASHA256;
  const now = setMilliseconds(new Date(), 0);
  const signatureInception = subSeconds(now, 1);
  const signatureExpiry = addMinutes(signatureInception, 10);

  let tldSigner: ZoneSigner;
  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(algorithm, RECORD_TLD);
  });

  describe('deserialise', () => {
    test('Malformed value should be refused', () => {
      // 3 octets means that the algorithm and public key are missing
      const malformedDnskey = Buffer.allocUnsafe(3);

      expect(() => DnskeyData.deserialise(malformedDnskey)).toThrowWithMessage(
        InvalidRdataError,
        'DNSKEY data is malformed',
      );
    });

    test('Public key should be extracted', () => {
      const record = tldSigner.generateDnskey(0).record;

      const data = DnskeyData.deserialise(record.dataSerialised);

      expect(data.publicKey.export({ format: 'der', type: 'spki' })).toEqual(
        tldSigner.publicKey.export({ format: 'der', type: 'spki' }),
      );
    });

    test('Algorithm should be extracted', () => {
      const record = tldSigner.generateDnskey(0).record;

      const data = DnskeyData.deserialise(record.dataSerialised);

      expect(data.algorithm).toEqual(algorithm);
    });

    test('Protocol should be extracted', () => {
      const protocol = 42;
      const record = tldSigner.generateDnskey(0, {}, protocol).record;

      const data = DnskeyData.deserialise(record.dataSerialised);

      expect(data.protocol).toEqual(protocol);
    });

    describe('Flags', () => {
      test('Zone Key should be on if set', () => {
        const record = tldSigner.generateDnskey(0, { zoneKey: true }).record;

        const data = DnskeyData.deserialise(record.dataSerialised);

        expect(data.flags.zoneKey).toBeTrue();
      });

      test('Zone Key should off if unset', () => {
        const record = tldSigner.generateDnskey(0, { zoneKey: false }).record;

        const data = DnskeyData.deserialise(record.dataSerialised);

        expect(data.flags.zoneKey).toBeFalse();
      });

      test('Secure Entrypoint should be on if set', () => {
        const record = tldSigner.generateDnskey(0, { secureEntryPoint: true }).record;

        const data = DnskeyData.deserialise(record.dataSerialised);

        expect(data.flags.secureEntryPoint).toBeTrue();
      });

      test('Secure Entrypoint should be off if unset', () => {
        const record = tldSigner.generateDnskey(0, { secureEntryPoint: false }).record;

        const data = DnskeyData.deserialise(record.dataSerialised);

        expect(data.flags.secureEntryPoint).toBeFalse();
      });
    });
  });

  describe('verifyRrsig', () => {
    const rrset = new RRSet([RECORD]);

    let dnskeyData: DnskeyData;
    beforeAll(() => {
      dnskeyData = tldSigner.generateDnskey(42).data;
    });

    test('Algorithm should match', async () => {
      const differentAlgorithm = DnssecAlgorithm.RSASHA512;
      expect(differentAlgorithm).not.toEqual(algorithm); // In case we change fixture inadvertently
      const { privateKey, publicKey } = await ZoneSigner.generate(differentAlgorithm, RECORD_TLD);
      const differentTldSigner = new ZoneSigner(
        tldSigner.keyTag,
        privateKey,
        publicKey,
        tldSigner.zoneName,
        differentAlgorithm,
      );
      const { data: rrsigData } = differentTldSigner.generateRrsig(rrset, now, signatureInception);

      expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.BOGUS);
    });

    describe('Validity period', () => {
      test('Expiry date equal to current time should be SECURE', () => {
        const { data: rrsigData } = tldSigner.generateRrsig(rrset, now, signatureInception);

        expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Expiry date later than current time should be SECURE', () => {
        const { data: rrsigData } = tldSigner.generateRrsig(
          rrset,
          addSeconds(now, 1),
          signatureInception,
        );

        expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Expiry date earlier than current time should be BOGUS', () => {
        const { data: rrsigData } = tldSigner.generateRrsig(
          rrset,
          subSeconds(now, 1),
          signatureInception,
        );

        expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.BOGUS);
      });

      test('Inception date equal to current time should be SECURE', () => {
        const { data: rrsigData } = tldSigner.generateRrsig(rrset, signatureExpiry, now);

        expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Inception date earlier than current time should be SECURE', () => {
        const { data: rrsigData } = tldSigner.generateRrsig(
          rrset,
          signatureExpiry,
          subSeconds(now, 1),
        );

        expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.SECURE);
      });

      test('Inception date later than current time should be BOGUS', () => {
        const { data: rrsigData } = tldSigner.generateRrsig(
          rrset,
          signatureExpiry,
          addSeconds(now, 1),
        );

        expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.BOGUS);
      });
    });

    test('Valid RRSIg should be SECURE', () => {
      const { data: rrsigData } = tldSigner.generateRrsig(
        rrset,
        signatureExpiry,
        signatureInception,
      );

      expect(dnskeyData.verifyRrsig(rrsigData, now)).toEqual(SecurityStatus.SECURE);
    });
  });
});
