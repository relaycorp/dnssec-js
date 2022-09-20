import { dnskey as DNSKEY, ds as DS, rrsig as RRSIG } from '@leichtgewicht/dns-packet';
import { addHours, getUnixTime } from 'date-fns';

import { ZoneSigner } from './ZoneSigner';
import { DNSSECAlgorithm } from '../DNSSECAlgorithm';
import { DigestAlgorithm } from '../DigestAlgorithm';
import { RRSet } from '../dns/RRSet';
import {
  RECORD_CLASS,
  RECORD_DATA,
  RECORD_TTL,
  RECORD_TYPE,
  RECORD_TYPE_ID,
} from '../../testUtils/stubs';
import { Record } from '../dns/Record';

describe('ZoneSigner', () => {
  test('generateDnskey', async () => {
    const signer = await ZoneSigner.generate(DNSSECAlgorithm.RSASHA256, '.');

    const dnskey = signer.generateDnskey(10, { secureEntryPoint: true });

    expect(dnskey.name).toEqual(signer.zoneName);
    const dnskeyParsed = DNSKEY.decode(lengthPrefixRdata(dnskey.data));
    expect(dnskeyParsed.algorithm).toEqual(DNSSECAlgorithm.RSASHA256);
  });

  test('generateDs', async () => {
    const signer = await ZoneSigner.generate(DNSSECAlgorithm.RSASHA256, '.');

    const digestAlgorithm = DigestAlgorithm.SHA256;
    const dskey = signer.generateDs('com', 10, digestAlgorithm);
    const rdata = lengthPrefixRdata(dskey.data);

    const parsed = DS.decode(rdata);

    expect(parsed).toMatchObject({
      algorithm: DNSSECAlgorithm.RSASHA256,
      digestType: digestAlgorithm,
      keyTag: signer.keyTag,
    });
  });

  test('generateRrsig', async () => {
    const dnssecAlgorithm = DNSSECAlgorithm.RSASHA256;
    const signer = await ZoneSigner.generate(dnssecAlgorithm, '.');
    const recordName = 'com.';

    const rrset = new RRSet([
      new Record(recordName, RECORD_TYPE_ID, RECORD_CLASS, RECORD_TTL, RECORD_DATA),
    ]);

    const signatureExpiry = addHours(new Date(), 3);
    const signatureInception = new Date();
    const rrsig = signer.generateRrsig(rrset, signatureExpiry, signatureInception);
    const rdata = lengthPrefixRdata(rrsig.data);

    const parsed = RRSIG.decode(rdata);

    expect(parsed.typeCovered).toEqual(RECORD_TYPE);
    expect(parsed.algorithm).toEqual(dnssecAlgorithm);
    expect(parsed.labels).toEqual(1);
    expect(parsed.originalTTL).toEqual(rrset.ttl);
    expect(parsed.expiration).toEqual(getUnixTime(signatureExpiry));
    expect(parsed.inception).toEqual(getUnixTime(signatureInception));
    expect(parsed.keyTag).toEqual(signer.keyTag);
    expect(parsed.signersName).toEqual(signer.zoneName);
  });

  test('generateRrsig with ECDSAP256SHA256', async () => {
    const dnssecAlgorithm = DNSSECAlgorithm.ECDSAP256SHA256;
    const signer = await ZoneSigner.generate(dnssecAlgorithm, '.');
    const recordName = 'com.';

    const rrset = new RRSet([
      new Record(recordName, RECORD_TYPE_ID, RECORD_CLASS, RECORD_TTL, RECORD_DATA),
    ]);

    const rrsig = signer.generateRrsig(rrset, addHours(new Date(), 3));
    const rdata = lengthPrefixRdata(rrsig.data);

    const parsed = RRSIG.decode(rdata);

    expect(parsed.algorithm).toEqual(dnssecAlgorithm);
  });
});

function lengthPrefixRdata(rdata: Buffer): Buffer {
  const prefix = Buffer.allocUnsafe(2);
  prefix.writeUInt16BE(rdata.byteLength);
  return Buffer.concat([prefix, rdata]);
}
