import { DsData } from './DsData';
import { InvalidRdataError } from '../errors';
import { ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';
import { DnskeyData } from './DnskeyData';
import { DnskeyRecord, DsRecord } from '../dnssecRecords';
import { serialiseName } from '../dns/name';
import { generateDigest } from '../utils/crypto';
import { copyDnssecRecordData } from '../../testUtils/dnssec';

describe('DsData', () => {
  let signer: ZoneSigner;
  let dnskey: DnskeyRecord;
  let ds: DsRecord;
  beforeAll(async () => {
    signer = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');

    dnskey = signer.generateDnskey(42);
    ds = signer.generateDs(dnskey, 'com', 5, DigestType.SHA384);
  });

  describe('deserialise', () => {
    let dsDataSerialised: Buffer;
    beforeAll(async () => {
      dsDataSerialised = ds.record.dataSerialised;
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

      expect(data.keyTag).toEqual(ds.data.keyTag);
    });

    test('Algorithm should be extracted', () => {
      const data = DsData.deserialise(dsDataSerialised);

      expect(data.algorithm).toEqual(dnskey.data.algorithm);
    });

    test('Digest type should be extracted', () => {
      const data = DsData.deserialise(dsDataSerialised);

      expect(data.digestType).toEqual(ds.data.digestType);
    });

    test('Digest should be extracted', () => {
      const data = DsData.deserialise(dsDataSerialised);

      expect(data.digest).toEqual(ds.data.digest);
    });
  });

  describe('calculateDnskeyDigest', () => {
    test.each([DigestType.SHA1, DigestType.SHA256, DigestType.SHA384])(
      'Hash %s should be supported',
      (digestType) => {
        const digest = DsData.calculateDnskeyDigest(dnskey, digestType);

        const expectedDigest = generateDigest(
          Buffer.concat([serialiseName(dnskey.record.name), dnskey.record.dataSerialised]),
          digestType,
        );
        expect(digest).toEqual(expectedDigest);
      },
    );
  });

  describe('verifyDnskey', () => {
    test('Key should be refused if Zone Key flag is off', () => {
      const invalidDnskeyData = new DnskeyData(
        dnskey.data.publicKey,
        dnskey.data.protocol,
        dnskey.data.algorithm,
        { ...dnskey.data.flags, zoneKey: false },
      );
      const invalidDnskey = copyDnssecRecordData(dnskey, invalidDnskeyData);

      expect(ds.data.verifyDnskey(invalidDnskey)).toBeFalse();
    });

    test('Serialisation should be refused if protocol is not 3', () => {
      const protocol = 42;
      const invalidDnskeyData = new DnskeyData(
        dnskey.data.publicKey,
        protocol,
        dnskey.data.algorithm,
        dnskey.data.flags,
      );
      const invalidDnskey = copyDnssecRecordData(dnskey, invalidDnskeyData);

      expect(ds.data.verifyDnskey(invalidDnskey)).toBeFalse();
    });

    test('Key should be refused if algorithm does not match', () => {
      const invalidDnskeyData = new DnskeyData(
        dnskey.data.publicKey,
        3,
        dnskey.data.algorithm + 1,
        dnskey.data.flags,
      );
      const invalidDnskey = copyDnssecRecordData(dnskey, invalidDnskeyData);

      expect(ds.data.verifyDnskey(invalidDnskey)).toBeFalse();
    });

    test('Key should be refused if digest does not match', () => {
      const anotherDs = new DsData(
        ds.data.keyTag,
        ds.data.algorithm,
        ds.data.digestType,
        Buffer.from('not a digest'),
      );

      expect(anotherDs.verifyDnskey(dnskey)).toBeFalse();
    });

    test('Key should be accepted if valid', () => {
      expect(ds.data.verifyDnskey(dnskey)).toBeTrue();
    });
  });
});
