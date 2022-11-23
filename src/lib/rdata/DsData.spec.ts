import { DsData } from './DsData';
import { ZoneSigner } from '../../testUtils/dnssec/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';
import { DnskeyData } from './DnskeyData';
import { DnskeyRecord, DsRecord } from '../dnssecRecords';
import { serialiseName } from '../dns/name';
import { generateDigest } from '../utils/crypto/hashing';
import { copyDnssecRecordData } from '../../testUtils/dnssec/records';
import { RECORD_TLD } from '../../testUtils/dnsStubs';

describe('DsData', () => {
  let signer: ZoneSigner;
  let dnskey: DnskeyRecord;
  let ds: DsRecord;
  beforeAll(async () => {
    signer = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');

    dnskey = signer.generateDnskey();
    ds = signer.generateDs(dnskey, RECORD_TLD, dnskey.data.calculateKeyTag());
  });

  describe('initFromPacket', () => {
    test('Key tag should be extracted', () => {
      const data = DsData.initFromPacket(ds.record.dataFields);

      expect(data.keyTag).toEqual(ds.data.keyTag);
    });

    test('Algorithm should be extracted', () => {
      const data = DsData.initFromPacket(ds.record.dataFields);

      expect(data.algorithm).toEqual(dnskey.data.algorithm);
    });

    test('Digest type should be extracted', () => {
      const data = DsData.initFromPacket(ds.record.dataFields);

      expect(data.digestType).toEqual(ds.data.digestType);
    });

    test('Digest should be extracted', () => {
      const data = DsData.initFromPacket(ds.record.dataFields);

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
      const invalidDnskeyData = new DnskeyData(dnskey.data.publicKey, dnskey.data.algorithm, {
        ...dnskey.data.flags,
        zoneKey: false,
      });
      const invalidDnskey = copyDnssecRecordData(dnskey, invalidDnskeyData);

      expect(ds.data.verifyDnskey(invalidDnskey)).toBeFalse();
    });

    test('Key should be refused if algorithm does not match', () => {
      const differentAlgorithm = DnssecAlgorithm.RSASHA1;
      expect(differentAlgorithm).not.toEqual(dnskey.data.algorithm);
      const invalidDnskeyData = new DnskeyData(
        dnskey.data.publicKey,
        differentAlgorithm,
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
