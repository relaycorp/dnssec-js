import { DS } from './DS';
import { DNSSECValidationError, InvalidRdataError } from '../../errors';
import { ZoneSigner } from '../../signing/ZoneSigner';
import { DNSSECAlgorithm } from '../../DNSSECAlgorithm';
import { DigestType } from '../../DigestType';
import { DNSKEY } from './DNSKEY';
import { DNSKEYFlags } from '../../DNSKEYFlags';
import { hashPublicKey } from '../../utils/crypto';

describe('DS', () => {
  const algorithm = DNSSECAlgorithm.RSASHA256;
  const digestType = DigestType.SHA384;

  let signer: ZoneSigner;
  beforeAll(async () => {
    signer = await ZoneSigner.generate(algorithm, '.');
  });

  describe('deserialise', () => {
    let dsDataSerialised: Buffer;
    beforeAll(async () => {
      dsDataSerialised = signer.generateDs('com', 5, digestType).data;
    });

    test('Malformed value should be refused', () => {
      // 3 octets means that the Digest Type and Digest are missing
      const malformedDSData = Buffer.allocUnsafe(3);

      expect(() => DS.deserialise(malformedDSData)).toThrowWithMessage(
        InvalidRdataError,
        'DS data is malformed',
      );
    });

    test('Empty digest value should be refused', () => {
      const malformedDSData = Buffer.allocUnsafe(4);

      expect(() => DS.deserialise(malformedDSData)).toThrowWithMessage(
        InvalidRdataError,
        'DS data is missing digest',
      );
    });

    test('Key tag should be extracted', () => {
      const data = DS.deserialise(dsDataSerialised);

      expect(data.keyTag).toEqual(signer.keyTag);
    });

    test('Algorithm should be extracted', () => {
      const data = DS.deserialise(dsDataSerialised);

      expect(data.algorithm).toEqual(algorithm);
    });

    test('Digest type should be extracted', () => {
      const data = DS.deserialise(dsDataSerialised);

      expect(data.digestType).toEqual(digestType);
    });

    test('Digest should be extracted', () => {
      const data = DS.deserialise(dsDataSerialised);

      const digest = hashPublicKey(signer.publicKey, digestType);
      expect(data.digest).toEqual(digest);
    });
  });

  describe('verifyDnskey', () => {
    let ds: DS;
    beforeAll(() => {
      ds = new DS(42, algorithm, digestType, hashPublicKey(signer.publicKey, digestType));
    });

    const dnskeyFlags: DNSKEYFlags = {
      zoneKey: true,
      secureEntryPoint: true,
    };

    test('Key should be refused if Zone Key flag is off', () => {
      const dnskey = new DNSKEY(signer.publicKey, 3, algorithm, { ...dnskeyFlags, zoneKey: false });

      expect(() => ds.verifyDnskey(dnskey)).toThrowWithMessage(
        DNSSECValidationError,
        'Zone Key flag is off',
      );
    });

    test('Serialisation should be refused if protocol is not 3', () => {
      const protocol = 42;
      const dnskey = new DNSKEY(signer.publicKey, protocol, algorithm, dnskeyFlags);

      expect(() => ds.verifyDnskey(dnskey)).toThrowWithMessage(
        DNSSECValidationError,
        `Protocol must be 3 (got ${protocol})`,
      );
    });

    test('Key should be refused if algorithm does not match', () => {
      const dnskey = new DNSKEY(signer.publicKey, 3, algorithm + 1, dnskeyFlags);

      expect(() => ds.verifyDnskey(dnskey)).toThrowWithMessage(
        DNSSECValidationError,
        `DS uses algorithm ${algorithm} but DNSKEY uses algorithm ${dnskey.algorithm}`,
      );
    });

    test('Key should be refused if digest does not match', () => {
      const anotherDs = new DS(signer.keyTag, algorithm, digestType, Buffer.from('not a digest'));
      const dnskey = new DNSKEY(signer.publicKey, 3, algorithm, dnskeyFlags);

      expect(() => anotherDs.verifyDnskey(dnskey)).toThrowWithMessage(
        DNSSECValidationError,
        'DNSKEY key digest does not match that of DS data',
      );
    });

    test('Key should be accepted if valid', () => {
      const dnskey = new DNSKEY(signer.publicKey, 3, algorithm, dnskeyFlags);

      ds.verifyDnskey(dnskey);
    });
  });
});
