import { addMinutes, addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { ZoneSigner } from '../signing/ZoneSigner';
import { DnskeyData } from './DnskeyData';
import { InvalidRdataError } from '../errors';
import { RECORD_TLD, RRSET } from '../../testUtils/dnsStubs';
import { DNSSEC_ROOT_DNSKEY_DATA, DNSSEC_ROOT_DNSKEY_KEY_TAG } from '../../testUtils/dnssec';
import { DatePeriod } from '../verification/DatePeriod';

describe('DnskeyData', () => {
  const NOW = setMilliseconds(new Date(), 0);
  const SIGNATURE_INCEPTION = subSeconds(NOW, 1);
  const SIGNATURE_EXPIRY = addMinutes(SIGNATURE_INCEPTION, 10);

  let tldSigner: ZoneSigner;
  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);
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

      expect(data.algorithm).toEqual(tldSigner.algorithm);
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

    test('Key tag should be cached', () => {
      const record = tldSigner.generateDnskey(0, { secureEntryPoint: false }).record;

      const data = DnskeyData.deserialise(record.dataSerialised);

      expect(data.keyTag).not.toBeNull();
    });
  });

  describe('calculateKeyTag', () => {
    test('Key tag should be calculated using algorithm in RFC 4034, Appendix B', () => {
      expect(DNSSEC_ROOT_DNSKEY_DATA.keyTag).toBeNull(); // Ensure it'll actually be calculated
      const keyTag = DNSSEC_ROOT_DNSKEY_DATA.calculateKeyTag();

      expect(keyTag).toEqual(DNSSEC_ROOT_DNSKEY_KEY_TAG);
    });

    test('Any value set at construction time should be honoured', () => {
      const customKeyTag = DNSSEC_ROOT_DNSKEY_DATA.calculateKeyTag() + 1;
      const dnskeyData = new DnskeyData(
        DNSSEC_ROOT_DNSKEY_DATA.publicKey,
        DNSSEC_ROOT_DNSKEY_DATA.protocol,
        DNSSEC_ROOT_DNSKEY_DATA.algorithm,
        DNSSEC_ROOT_DNSKEY_DATA.flags,
        customKeyTag,
      );

      expect(dnskeyData.calculateKeyTag()).toEqual(customKeyTag);
    });
  });

  describe('verifyRrsig', () => {
    const VALIDITY_PERIOD = DatePeriod.init(subSeconds(NOW, 1), addSeconds(NOW, 1));

    let dnskeyData: DnskeyData;
    beforeAll(() => {
      dnskeyData = tldSigner.generateDnskey(42).data;
    });

    test('Algorithm should match', async () => {
      const differentAlgorithm = DnssecAlgorithm.RSASHA512;
      expect(differentAlgorithm).not.toEqual(tldSigner.algorithm); // In case we change fixture
      const { privateKey, publicKey } = await ZoneSigner.generate(differentAlgorithm, RECORD_TLD);
      const differentTldSigner = new ZoneSigner(
        privateKey,
        publicKey,
        tldSigner.zoneName,
        differentAlgorithm,
      );
      const { data: rrsigData } = differentTldSigner.generateRrsig(
        RRSET,
        dnskeyData.calculateKeyTag(),
        NOW,
        SIGNATURE_INCEPTION,
      );

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeFalse();
    });

    test('Key tag should match', async () => {
      const differentKeyTag = dnskeyData.calculateKeyTag() + 1;
      const { data: rrsigData } = tldSigner.generateRrsig(
        RRSET,
        differentKeyTag,
        NOW,
        SIGNATURE_INCEPTION,
      );

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeFalse();
    });

    test('Signature validity outside required period should be BOGUS', () => {
      const { data: rrsigData } = tldSigner.generateRrsig(
        RRSET,
        dnskeyData.calculateKeyTag(),
        subSeconds(VALIDITY_PERIOD.start, 1),
        subSeconds(VALIDITY_PERIOD.start, 2),
      );

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeFalse();
    });

    test('Valid RRSIg should be SECURE', () => {
      const { data: rrsigData } = tldSigner.generateRrsig(
        RRSET,
        dnskeyData.calculateKeyTag(),
        SIGNATURE_EXPIRY,
        SIGNATURE_INCEPTION,
      );

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeTrue();
    });
  });
});
