import { DsData } from './DsData';
import { DnssecValidationError, InvalidRdataError } from '../errors';
import { ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';
import { DnskeyData } from './DnskeyData';
import { DnskeyFlags } from '../DnskeyFlags';
import { hashPublicKey } from '../utils/crypto';

describe('DsData', () => {
  const algorithm = DnssecAlgorithm.RSASHA256;
  const digestType = DigestType.SHA384;

  let signer: ZoneSigner;
  beforeAll(async () => {
    signer = await ZoneSigner.generate(algorithm, '.');
  });

  describe('deserialise', () => {
    let dsDataSerialised: Buffer;
    beforeAll(async () => {
      dsDataSerialised = signer.generateDs('com', 5, digestType).dataSerialised;
    });

    test('Malformed value should be refused', () => {
      // 3 octets means that the Digest Type and Digest are missing
      const malformedDSData = Buffer.allocUnsafe(3);

      expect(() => DsData.deserialise(malformedDSData)).toThrowWithMessage(
        InvalidRdataError,
        'DS data is malformed',
      );
    });

    test('Empty digest value should be refused', () => {
      const malformedDsData = Buffer.allocUnsafe(4);

      expect(() => DsData.deserialise(malformedDsData)).toThrowWithMessage(
        InvalidRdataError,
        'DS data is missing digest',
      );
    });

    test('Key tag should be extracted', () => {
      const data = DsData.deserialise(dsDataSerialised);

      expect(data.keyTag).toEqual(signer.keyTag);
    });

    test('Algorithm should be extracted', () => {
      const data = DsData.deserialise(dsDataSerialised);

      expect(data.algorithm).toEqual(algorithm);
    });

    test('Digest type should be extracted', () => {
      const data = DsData.deserialise(dsDataSerialised);

      expect(data.digestType).toEqual(digestType);
    });

    test('Digest should be extracted', () => {
      const data = DsData.deserialise(dsDataSerialised);

      const digest = hashPublicKey(signer.publicKey, digestType);
      expect(data.digest).toEqual(digest);
    });
  });

  describe('verifyDnskey', () => {
    let ds: DsData;
    beforeAll(() => {
      ds = new DsData(42, algorithm, digestType, hashPublicKey(signer.publicKey, digestType));
    });

    const dnskeyFlags: DnskeyFlags = {
      zoneKey: true,
      secureEntryPoint: true,
    };

    test('Key should be refused if Zone Key flag is off', () => {
      const dnskey = new DnskeyData(signer.publicKey, 3, algorithm, {
        ...dnskeyFlags,
        zoneKey: false,
      });

      expect(() => ds.verifyDnskey(dnskey)).toThrowWithMessage(
        DnssecValidationError,
        'Zone Key flag is off',
      );
    });

    test('Serialisation should be refused if protocol is not 3', () => {
      const protocol = 42;
      const dnskey = new DnskeyData(signer.publicKey, protocol, algorithm, dnskeyFlags);

      expect(() => ds.verifyDnskey(dnskey)).toThrowWithMessage(
        DnssecValidationError,
        `Protocol must be 3 (got ${protocol})`,
      );
    });

    test('Key should be refused if algorithm does not match', () => {
      const dnskey = new DnskeyData(signer.publicKey, 3, algorithm + 1, dnskeyFlags);

      expect(() => ds.verifyDnskey(dnskey)).toThrowWithMessage(
        DnssecValidationError,
        `DS uses algorithm ${algorithm} but DNSKEY uses algorithm ${dnskey.algorithm}`,
      );
    });

    test('Key should be refused if digest does not match', () => {
      const anotherDs = new DsData(
        signer.keyTag,
        algorithm,
        digestType,
        Buffer.from('not a digest'),
      );
      const dnskey = new DnskeyData(signer.publicKey, 3, algorithm, dnskeyFlags);

      expect(() => anotherDs.verifyDnskey(dnskey)).toThrowWithMessage(
        DnssecValidationError,
        'DNSKEY key digest does not match that of DS data',
      );
    });

    test('Key should be accepted if valid', () => {
      const dnskey = new DnskeyData(signer.publicKey, 3, algorithm, dnskeyFlags);

      ds.verifyDnskey(dnskey);
    });
  });
});
