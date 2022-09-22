import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { ZoneSigner } from '../../signing/ZoneSigner';
import { DNSKEY } from './DNSKEY';
import { InvalidRdataError } from '../../errors';

describe('DNSKEY', () => {
  describe('deserialise', () => {
    const algorithm = DNSSECAlgorithm.RSASHA256;

    let signer: ZoneSigner;
    beforeAll(async () => {
      signer = await ZoneSigner.generate(algorithm, '.');
    });

    test('Malformed value should be refused', () => {
      // 3 octets means that the algorithm and public key are missing
      const malformedDnskey = Buffer.allocUnsafe(3);

      expect(() => DNSKEY.deserialise(malformedDnskey)).toThrowWithMessage(
        InvalidRdataError,
        'DNSKEY data is malformed',
      );
    });

    test('Serialisation should be refused if public key is missing', () => {
      // 4 octets means that the public key is missing
      const malformedDnskey = Buffer.allocUnsafe(4);

      expect(() => DNSKEY.deserialise(malformedDnskey)).toThrowWithMessage(
        InvalidRdataError,
        'DNSKEY data is missing public key',
      );
    });

    test('Public key should be extracted', () => {
      const record = signer.generateDnskey(0);

      const data = DNSKEY.deserialise(record.data);

      expect(data.publicKey.export({ format: 'der', type: 'spki' })).toEqual(
        signer.publicKey.export({ format: 'der', type: 'spki' }),
      );
    });

    test('Algorithm should be extracted', () => {
      const record = signer.generateDnskey(0);

      const data = DNSKEY.deserialise(record.data);

      expect(data.algorithm).toEqual(algorithm);
    });

    test('Protocol should be extracted', () => {
      const protocol = 42;
      const record = signer.generateDnskey(0, {}, protocol);

      const data = DNSKEY.deserialise(record.data);

      expect(data.protocol).toEqual(protocol);
    });

    describe('Flags', () => {
      test('Zone Key should be on if set', () => {
        const record = signer.generateDnskey(0, { zoneKey: true });

        const data = DNSKEY.deserialise(record.data);

        expect(data.flags.zoneKey).toBeTrue();
      });

      test('Zone Key should off if unset', () => {
        const record = signer.generateDnskey(0, { zoneKey: false });

        const data = DNSKEY.deserialise(record.data);

        expect(data.flags.zoneKey).toBeFalse();
      });

      test('Secure Entrypoint should be on if set', () => {
        const record = signer.generateDnskey(0, { secureEntryPoint: true });

        const data = DNSKEY.deserialise(record.data);

        expect(data.flags.secureEntryPoint).toBeTrue();
      });

      test('Secure Entrypoint should be off if unset', () => {
        const record = signer.generateDnskey(0, { secureEntryPoint: false });

        const data = DNSKEY.deserialise(record.data);

        expect(data.flags.secureEntryPoint).toBeFalse();
      });
    });
  });
});
