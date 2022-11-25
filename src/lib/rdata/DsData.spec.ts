import type { DigestData } from '@leichtgewicht/dns-packet';

import { ZoneSigner } from '../../testUtils/dnssec/ZoneSigner.js';
import { DnssecAlgorithm } from '../DnssecAlgorithm.js';
import { DigestType } from '../DigestType.js';
import type { DnskeyRecord, DsRecord } from '../dnssecRecords.js';
import { serialiseName } from '../dns/name.js';
import { generateDigest } from '../utils/crypto/hashing.js';
import { copyDnssecRecordData } from '../../testUtils/dnssec/records.js';
import { RECORD_TLD } from '../../testUtils/dnsStubs.js';

import { DnskeyData } from './DnskeyData.js';
import { DsData } from './DsData.js';

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
      const data = DsData.initFromPacket(ds.record.dataFields as DigestData);

      expect(data.keyTag).toStrictEqual(ds.data.keyTag);
    });

    test('Algorithm should be extracted', () => {
      const data = DsData.initFromPacket(ds.record.dataFields as DigestData);

      expect(data.algorithm).toStrictEqual(dnskey.data.algorithm);
    });

    test('Digest type should be extracted', () => {
      const data = DsData.initFromPacket(ds.record.dataFields as DigestData);

      expect(data.digestType).toStrictEqual(ds.data.digestType);
    });

    test('Digest should be extracted', () => {
      const data = DsData.initFromPacket(ds.record.dataFields as DigestData);

      expect(data.digest).toStrictEqual(ds.data.digest);
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
        expect(digest).toStrictEqual(expectedDigest);
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
      expect(differentAlgorithm).not.toStrictEqual(dnskey.data.algorithm);
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
