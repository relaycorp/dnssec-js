import { dnskey as DNSKEY, ds as DS } from '@leichtgewicht/dns-packet';

import { ZoneSigner } from './ZoneSigner';
import { DNSSECAlgorithm } from '../DNSSECAlgorithm';
import { DigestAlgorithm } from '../DigestAlgorithm';

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
});

function lengthPrefixRdata(rdata: Buffer): Buffer {
  const prefix = Buffer.allocUnsafe(2);
  prefix.writeUInt16BE(rdata.byteLength);
  return Buffer.concat([prefix, rdata]);
}
