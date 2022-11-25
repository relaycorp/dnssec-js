import type { DNSKeyData } from '@leichtgewicht/dns-packet';
import { addMinutes, addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm.js';
import { ZoneSigner } from '../../testUtils/dnssec/ZoneSigner.js';
import { RECORD_TLD, RRSET } from '../../testUtils/dnsStubs.js';
import { DatePeriod } from '../DatePeriod.js';
import {
  DNSSEC_ROOT_DNSKEY_DATA,
  DNSSEC_ROOT_DNSKEY_KEY_TAG,
} from '../../testUtils/dnssec/iana.js';
import type { SignatureGenerationOptions } from '../../testUtils/dnssec/SignatureGenerationOptions.js';

import { DnskeyData } from './DnskeyData.js';

describe('DnskeyData', () => {
  const NOW = setMilliseconds(new Date(), 0);
  const SIGNATURE_INCEPTION = subSeconds(NOW, 1);
  const SIGNATURE_EXPIRY = addMinutes(SIGNATURE_INCEPTION, 10);

  let tldSigner: ZoneSigner;

  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);
  });

  describe('initFromPacket', () => {
    test('Public key should be extracted', () => {
      const { record } = tldSigner.generateDnskey();

      const data = DnskeyData.initFromPacket(
        record.dataFields as DNSKeyData,
        record.dataSerialised,
      );

      expect(data.publicKey.export({ format: 'der', type: 'spki' })).toStrictEqual(
        tldSigner.publicKey.export({ format: 'der', type: 'spki' }),
      );
    });

    test('Algorithm should be extracted', () => {
      const { record } = tldSigner.generateDnskey();

      const data = DnskeyData.initFromPacket(
        record.dataFields as DNSKeyData,
        record.dataSerialised,
      );

      expect(data.algorithm).toStrictEqual(tldSigner.algorithm);
    });

    describe('Flags', () => {
      test('Zone Key should be on if set', () => {
        const { record } = tldSigner.generateDnskey({ flags: { zoneKey: true } });

        const data = DnskeyData.initFromPacket(
          record.dataFields as DNSKeyData,
          record.dataSerialised,
        );

        expect(data.flags.zoneKey).toBeTrue();
      });

      test('Zone Key should off if unset', () => {
        const { record } = tldSigner.generateDnskey({ flags: { zoneKey: false } });

        const data = DnskeyData.initFromPacket(
          record.dataFields as DNSKeyData,
          record.dataSerialised,
        );

        expect(data.flags.zoneKey).toBeFalse();
      });

      test('Secure Entrypoint should be on if set', () => {
        const { record } = tldSigner.generateDnskey({ flags: { secureEntryPoint: true } });

        const data = DnskeyData.initFromPacket(
          record.dataFields as DNSKeyData,
          record.dataSerialised,
        );

        expect(data.flags.secureEntryPoint).toBeTrue();
      });

      test('Secure Entrypoint should be off if unset', () => {
        const { record } = tldSigner.generateDnskey({ flags: { secureEntryPoint: false } });

        const data = DnskeyData.initFromPacket(
          record.dataFields as DNSKeyData,
          record.dataSerialised,
        );

        expect(data.flags.secureEntryPoint).toBeFalse();
      });
    });

    test('Key tag should be cached', () => {
      const { record } = tldSigner.generateDnskey({ flags: { secureEntryPoint: false } });

      const data = DnskeyData.initFromPacket(
        record.dataFields as DNSKeyData,
        record.dataSerialised,
      );

      expect(data.keyTag).not.toBeNull();
    });
  });

  describe('calculateKeyTag', () => {
    test('Key tag should be calculated using algorithm in RFC 4034, Appendix B', () => {
      expect(DNSSEC_ROOT_DNSKEY_DATA.keyTag).toBeNull(); // Ensure it'll actually be calculated
      const keyTag = DNSSEC_ROOT_DNSKEY_DATA.calculateKeyTag();

      expect(keyTag).toStrictEqual(DNSSEC_ROOT_DNSKEY_KEY_TAG);
    });

    test('Any value set at construction time should be honoured', () => {
      const customKeyTag = DNSSEC_ROOT_DNSKEY_DATA.calculateKeyTag() + 1;
      const dnskeyData = new DnskeyData(
        DNSSEC_ROOT_DNSKEY_DATA.publicKey,
        DNSSEC_ROOT_DNSKEY_DATA.algorithm,
        DNSSEC_ROOT_DNSKEY_DATA.flags,
        customKeyTag,
      );

      expect(dnskeyData.calculateKeyTag()).toStrictEqual(customKeyTag);
    });
  });

  describe('verifyRrsig', () => {
    const VALIDITY_PERIOD = DatePeriod.init(subSeconds(NOW, 1), addSeconds(NOW, 1));
    const RRSIG_OPTIONS: SignatureGenerationOptions = {
      signatureExpiry: SIGNATURE_EXPIRY,
      signatureInception: NOW,
    };

    let dnskeyData: DnskeyData;

    beforeAll(() => {
      dnskeyData = tldSigner.generateDnskey().data;
    });

    test('Algorithm should match', async () => {
      const differentAlgorithm = DnssecAlgorithm.RSASHA512;
      expect(differentAlgorithm).not.toStrictEqual(tldSigner.algorithm); // In case it ever changes
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
        RRSIG_OPTIONS,
      );

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeFalse();
    });

    test('Key tag should match', () => {
      const differentKeyTag = dnskeyData.calculateKeyTag() + 1;
      const { data: rrsigData } = tldSigner.generateRrsig(RRSET, differentKeyTag, RRSIG_OPTIONS);

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeFalse();
    });

    test('Signature validity be within required period', () => {
      const { data: rrsigData } = tldSigner.generateRrsig(RRSET, dnskeyData.calculateKeyTag(), {
        signatureExpiry: subSeconds(VALIDITY_PERIOD.start, 1),
        signatureInception: subSeconds(VALIDITY_PERIOD.start, 2),
      });

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeFalse();
    });

    test('Valid RRSIg should be SECURE', () => {
      const { data: rrsigData } = tldSigner.generateRrsig(
        RRSET,
        dnskeyData.calculateKeyTag(),
        RRSIG_OPTIONS,
      );

      expect(dnskeyData.verifyRrsig(rrsigData, VALIDITY_PERIOD)).toBeTrue();
    });
  });
});
