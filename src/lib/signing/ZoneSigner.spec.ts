import { dnskey as DNSKEY, ds as DS, rrsig as RRSIG } from '@leichtgewicht/dns-packet';
import { addHours, getUnixTime, setMilliseconds } from 'date-fns';

import { ZoneSigner } from './ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';
import { RRSet } from '../dns/RRSet';
import { QUESTION, RECORD, RECORD_TYPE_STR } from '../../testUtils/dnsStubs';
import { generateDigest } from '../utils/crypto';
import { serialiseName } from '../dns/name';

describe('ZoneSigner', () => {
  test('generateDnskey', async () => {
    const signer = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');

    const dnskey = signer.generateDnskey(10, { secureEntryPoint: true }).record;

    expect(dnskey.name).toEqual(signer.zoneName);
    const dnskeyParsed = DNSKEY.decode(lengthPrefixRdata(dnskey.dataSerialised));
    expect(dnskeyParsed.algorithm).toEqual(DnssecAlgorithm.RSASHA256);
  });

  test('generateDs', async () => {
    const signer = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');
    const digestAlgorithm = DigestType.SHA256;
    const dnskey = signer.generateDnskey(42);

    const dskey = signer.generateDs(dnskey, 'com', 10, digestAlgorithm);

    const rdata = lengthPrefixRdata(dskey.record.dataSerialised);
    const parsed = DS.decode(rdata);
    expect(parsed).toMatchObject({
      algorithm: DnssecAlgorithm.RSASHA256,
      digest: generateDigest(
        Buffer.concat([serialiseName(signer.zoneName), dnskey.record.dataSerialised]),
        digestAlgorithm,
      ),
      digestType: digestAlgorithm,
      keyTag: dnskey.data.calculateKeyTag(),
    });
  });

  test('generateRrsig', async () => {
    const dnssecAlgorithm = DnssecAlgorithm.RSASHA256;
    const signer = await ZoneSigner.generate(dnssecAlgorithm, '.');
    const recordName = 'com.';
    const rrset = RRSet.init({ ...QUESTION, name: recordName }, [
      RECORD.shallowCopy({ name: recordName }),
    ]);
    const signatureExpiry = setMilliseconds(addHours(new Date(), 3), 5);
    const signatureInception = setMilliseconds(new Date(), 5);
    const keyTag = 12345;

    const rrsig = signer.generateRrsig(rrset, keyTag, signatureExpiry, signatureInception);

    const rdata = lengthPrefixRdata(rrsig.record.dataSerialised);
    const parsed = RRSIG.decode(rdata);
    expect(parsed.typeCovered).toEqual(RECORD_TYPE_STR);
    expect(parsed.algorithm).toEqual(dnssecAlgorithm);
    expect(parsed.labels).toEqual(1);
    expect(parsed.originalTTL).toEqual(rrset.ttl);
    expect(parsed.expiration).toEqual(getUnixTime(setMilliseconds(signatureExpiry, 0)));
    expect(parsed.inception).toEqual(getUnixTime(setMilliseconds(signatureInception, 0)));
    expect(parsed.keyTag).toEqual(keyTag);
    expect(`${parsed.signersName}.`).toEqual(recordName);
  });

  test('generateRrsig with ED448', async () => {
    const dnssecAlgorithm = DnssecAlgorithm.ED448;
    const signer = await ZoneSigner.generate(dnssecAlgorithm, '.');
    const recordName = 'com.';

    const rrset = RRSet.init({ ...QUESTION, name: recordName }, [
      RECORD.shallowCopy({ name: recordName }),
    ]);

    const rrsig = signer.generateRrsig(rrset, 42, addHours(new Date(), 3));
    const rdata = lengthPrefixRdata(rrsig.record.dataSerialised);

    const parsed = RRSIG.decode(rdata);

    expect(parsed.algorithm).toEqual(dnssecAlgorithm);
  });
});

function lengthPrefixRdata(rdata: Buffer): Buffer {
  const prefix = Buffer.allocUnsafe(2);
  prefix.writeUInt16BE(rdata.byteLength);
  return Buffer.concat([prefix, rdata]);
}
