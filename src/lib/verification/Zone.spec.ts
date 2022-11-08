import { addSeconds } from 'date-fns';

import { ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { RECORD, RECORD_LABEL, RECORD_TLD } from '../../testUtils/dnsStubs';
import { Zone } from './Zone';
import { Message } from '../dns/Message';
import { SecurityStatus } from './SecurityStatus';
import { DnskeyRecord, DsRecord, RrsigRecord } from '../dnssecRecords';
import { DsData } from '../rdata/DsData';
import { RRSet } from '../dns/RRSet';
import { RrsigData } from '../rdata/RrsigData';
import { FailureResult, SuccessfulResult } from './VerificationResult';
import { DnskeyData } from '../rdata/DnskeyData';
import { copyDnssecRecordData } from '../../testUtils/dnssec';
import { Question } from '../dns/Question';
import { DNSClass } from '../dns/DNSClass';
import { DnssecRecordType } from '../DnssecRecordType';

describe('Zone', () => {
  const ZONE_NAME = RECORD.name;
  const DNSKEY_QUESTION: Question = {
    class: DNSClass.IN,
    name: ZONE_NAME,
    type: DnssecRecordType.DNSKEY,
  };

  let apexSigner: ZoneSigner;
  let dnskey: DnskeyRecord;
  let dnskeyRrsig: RrsigRecord;
  beforeAll(async () => {
    apexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD.name);

    dnskey = apexSigner.generateDnskey(60);
    dnskeyRrsig = apexSigner.generateRrsig(
      RRSet.init(DNSKEY_QUESTION, [dnskey.record]),
      dnskey.data.calculateKeyTag(),
      addSeconds(new Date(), 60),
    );
  });

  let tldSigner: ZoneSigner;
  let ds: DsRecord;
  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);

    ds = tldSigner.generateDs(dnskey, RECORD_LABEL, 60);
  });

  describe('init', () => {
    test('Message with rcode other than NOERROR should be BOGUS', () => {
      const rcode = 1;
      const dnskeyMessage = new Message({ rcode }, [dnskey.record, dnskeyRrsig.record]);

      const result = Zone.init(ZONE_NAME, dnskeyMessage, [ds.data], new Date());

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: [`Expected DNSKEY rcode to be NOERROR (0; got ${rcode})`],
      });
    });

    test('Malformed DNSKEY should be BOGUS', () => {
      const malformedDnskey = dnskey.record.shallowCopy({ dataSerialised: Buffer.from('hi') });
      const newRrsig = apexSigner.generateRrsig(
        RRSet.init(DNSKEY_QUESTION, [malformedDnskey]),
        dnskeyRrsig.data.keyTag,
        dnskeyRrsig.data.signatureExpiry,
      );
      const dnskeyMessage = new Message({ rcode: 0 }, [malformedDnskey, newRrsig.record]);

      const result = Zone.init(ZONE_NAME, dnskeyMessage, [ds.data], new Date());

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['Found malformed DNSKEY'],
      });
    });

    test('DNSKEY without matching DS should be BOGUS', () => {
      const mismatchingDsData = new DsData(
        ds.data.keyTag,
        ds.data.algorithm + 1,
        ds.data.digestType,
        ds.data.digest,
      );

      const result = Zone.init(
        ZONE_NAME,
        new Message({ rcode: 0 }, [dnskey.record, dnskeyRrsig.record]),
        [mismatchingDsData],
        new Date(),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No DNSKEY matched specified DS(s)'],
      });
    });

    test('Valid RRSig for non-matching DNSKEY should be BOGUS', () => {
      const mismatchingDnskeyRrsigData = new RrsigData(
        dnskeyRrsig.data.type,
        dnskeyRrsig.data.algorithm + 1,
        dnskeyRrsig.data.labels,
        dnskeyRrsig.data.ttl,
        dnskeyRrsig.data.signatureExpiry,
        dnskeyRrsig.data.signatureInception,
        dnskeyRrsig.data.keyTag,
        dnskeyRrsig.data.signerName,
        dnskeyRrsig.data.signature,
      );
      const mismatchingDnskeyRrsig = dnskeyRrsig.record.shallowCopy({
        dataSerialised: mismatchingDnskeyRrsigData.serialise(),
      });
      const result = Zone.init(
        ZONE_NAME,
        new Message({ rcode: 0 }, [dnskey.record, mismatchingDnskeyRrsig]),
        [ds.data],
        new Date(),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });

    test('Invalid RRSig for matching DNSKEY should be BOGUS', () => {
      const mismatchingDnskeyRrsigData = new RrsigData(
        dnskeyRrsig.data.type,
        dnskeyRrsig.data.algorithm,
        dnskeyRrsig.data.labels,
        dnskeyRrsig.data.ttl,
        dnskeyRrsig.data.signatureExpiry,
        dnskeyRrsig.data.signatureInception,
        dnskeyRrsig.data.keyTag + 1,
        dnskeyRrsig.data.signerName,
        dnskeyRrsig.data.signature,
      );
      const mismatchingDnskeyRrsig = dnskeyRrsig.record.shallowCopy({
        dataSerialised: mismatchingDnskeyRrsigData.serialise(),
      });
      const result = Zone.init(
        ZONE_NAME,
        new Message({ rcode: 0 }, [dnskey.record, mismatchingDnskeyRrsig]),
        [ds.data],
        new Date(),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });

    test('Expired RRSig should be BOGUS', () => {
      const result = Zone.init(
        ZONE_NAME,
        new Message({ rcode: 0 }, [dnskey.record, dnskeyRrsig.record]),
        [ds.data],
        addSeconds(dnskeyRrsig.data.signatureExpiry, 1),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });

    test('DNSKEY should be BOGUS if it is not a ZSK', () => {
      const nonZskDnskeyData = new DnskeyData(
        dnskey.data.publicKey,
        dnskey.data.protocol,
        dnskey.data.algorithm,
        { ...dnskey.data.flags, zoneKey: false },
      );
      const nonZskDnskeyRecord = copyDnssecRecordData(dnskey, nonZskDnskeyData);
      const rrsig = apexSigner.generateRrsig(
        RRSet.init(DNSKEY_QUESTION, [nonZskDnskeyRecord.record]),
        nonZskDnskeyData.calculateKeyTag(),
        dnskeyRrsig.data.signatureExpiry,
        dnskeyRrsig.data.signatureInception,
      );
      const nonZskDs = tldSigner.generateDs(
        nonZskDnskeyRecord,
        RECORD_LABEL,
        ds.record.ttl,
        ds.data.digestType,
      );
      const result = Zone.init(
        ZONE_NAME,
        new Message({ rcode: 0 }, [nonZskDnskeyRecord.record, rrsig.record]),
        [nonZskDs.data],
        new Date(),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No DNSKEY matched specified DS(s)'],
      });
    });

    test('Zone should be initialised if ZSK is found', () => {
      const result = Zone.init(
        ZONE_NAME,
        new Message({ rcode: 0 }, [dnskey.record, dnskeyRrsig.record]),
        [ds.data],
        new Date(),
      );

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      expect(zone.name).toEqual(RECORD.name);
      expect(zone.dnskeys).toHaveLength(1);
      expect(zone.dnskeys[0].calculateKeyTag()).toEqual(dnskey.data.calculateKeyTag());
    });

    test('Other DNSKEYs should also be stored if a valid ZSK is found', async () => {
      const newApexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA1, apexSigner.zoneName);
      const nonZskDnskey = newApexSigner.generateDnskey(dnskey.record.ttl, { zoneKey: false });
      const newRrsig = apexSigner.generateRrsig(
        RRSet.init(DNSKEY_QUESTION, [dnskey.record, nonZskDnskey.record]),
        dnskey.data.calculateKeyTag(),
        dnskeyRrsig.data.signatureExpiry,
        dnskeyRrsig.data.signatureInception,
      );

      const result = Zone.init(
        ZONE_NAME,
        new Message({ rcode: 0 }, [dnskey.record, nonZskDnskey.record, newRrsig.record]),
        [ds.data],
        new Date(),
      );

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      const dnskeyTags = zone.dnskeys.map((k) => k.calculateKeyTag());
      expect(dnskeyTags).toContainAllValues([
        dnskey.data.calculateKeyTag(),
        nonZskDnskey.data.calculateKeyTag(),
      ]);
    });
  });

  // describe('verifyRrset', () => {
  //   test.todo('RRSig signer name must match zone name');
  //
  //   test.todo('RRSig key tag should match a DNSKEY');
  //
  //   test.todo('Non-ZSK should be allowed to sign RRset');
  // });
});
