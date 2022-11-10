import { addSeconds } from 'date-fns';

import { ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { QUESTION, RECORD, RECORD_TLD } from '../../testUtils/dnsStubs';
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
import { RCode } from '../dns/RCode';
import { SignedRRSet } from './SignedRRSet';

describe('Zone', () => {
  const TLD_DNSKEY_QUESTION: Question = {
    class: DNSClass.IN,
    name: RECORD_TLD,
    type: DnssecRecordType.DNSKEY,
  };

  let rootSigner: ZoneSigner;
  let rootDnskey: DnskeyRecord;
  let rootDnskeyRrsig: RrsigRecord;
  let rootDs: DsRecord;
  beforeAll(async () => {
    rootSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');

    rootDnskey = rootSigner.generateDnskey(42, { zoneKey: true });
    const rootDnskeyRrset = RRSet.init(
      { class: DNSClass.IN, name: '.', type: DnssecRecordType.DNSKEY },
      [rootDnskey.record],
    );
    rootDnskeyRrsig = rootSigner.generateRrsig(
      rootDnskeyRrset,
      rootDnskey.data.calculateKeyTag(),
      addSeconds(new Date(), 60),
    );

    rootDs = rootSigner.generateDs(rootDnskey, '.', 42);
  });

  let tldSigner: ZoneSigner;
  let tldDnskey: DnskeyRecord;
  let tldDnskeyRrsig: RrsigRecord;
  let tldDs: DsRecord;
  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);

    tldDnskey = tldSigner.generateDnskey(60);
    tldDnskeyRrsig = tldSigner.generateRrsig(
      RRSet.init(TLD_DNSKEY_QUESTION, [tldDnskey.record]),
      tldDnskey.data.calculateKeyTag(),
      addSeconds(new Date(), 60),
    );

    tldDs = rootSigner.generateDs(tldDnskey, RECORD_TLD, 60);
  });

  describe('init', () => {
    test('Message with rcode other than NOERROR should be BOGUS', () => {
      const rcode = 1;
      const dnskeyMessage = new Message({ rcode }, [tldDnskey.record, tldDnskeyRrsig.record]);

      const result = Zone.init(RECORD_TLD, dnskeyMessage, [tldDs.data], new Date());

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: [`Expected DNSKEY rcode to be NOERROR (0; got ${rcode})`],
      });
    });

    test('Malformed DNSKEY data should be BOGUS', () => {
      const malformedDnskey = tldDnskey.record.shallowCopy({ dataSerialised: Buffer.from('hi') });
      const newRrsig = tldSigner.generateRrsig(
        RRSet.init(TLD_DNSKEY_QUESTION, [malformedDnskey]),
        tldDnskeyRrsig.data.keyTag,
        tldDnskeyRrsig.data.signatureExpiry,
      );
      const dnskeyMessage = new Message({ rcode: RCode.NoError }, [
        malformedDnskey,
        newRrsig.record,
      ]);

      const result = Zone.init(RECORD_TLD, dnskeyMessage, [tldDs.data], new Date());

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['Found malformed DNSKEY rdata'],
      });
    });

    test('DNSKEY without matching DS should be BOGUS', () => {
      const mismatchingDsData = new DsData(
        tldDs.data.keyTag,
        tldDs.data.algorithm + 1,
        tldDs.data.digestType,
        tldDs.data.digest,
      );

      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [tldDnskey.record, tldDnskeyRrsig.record]),
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
        tldDnskeyRrsig.data.type,
        tldDnskeyRrsig.data.algorithm + 1,
        tldDnskeyRrsig.data.labels,
        tldDnskeyRrsig.data.ttl,
        tldDnskeyRrsig.data.signatureExpiry,
        tldDnskeyRrsig.data.signatureInception,
        tldDnskeyRrsig.data.keyTag,
        tldDnskeyRrsig.data.signerName,
        tldDnskeyRrsig.data.signature,
      );
      const mismatchingDnskeyRrsig = tldDnskeyRrsig.record.shallowCopy({
        dataSerialised: mismatchingDnskeyRrsigData.serialise(),
      });
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [tldDnskey.record, mismatchingDnskeyRrsig]),
        [tldDs.data],
        new Date(),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });

    test('Invalid RRSig for matching DNSKEY should be BOGUS', () => {
      const mismatchingDnskeyRrsigData = new RrsigData(
        tldDnskeyRrsig.data.type,
        tldDnskeyRrsig.data.algorithm,
        tldDnskeyRrsig.data.labels,
        tldDnskeyRrsig.data.ttl,
        tldDnskeyRrsig.data.signatureExpiry,
        tldDnskeyRrsig.data.signatureInception,
        tldDnskeyRrsig.data.keyTag + 1,
        tldDnskeyRrsig.data.signerName,
        tldDnskeyRrsig.data.signature,
      );
      const mismatchingDnskeyRrsig = tldDnskeyRrsig.record.shallowCopy({
        dataSerialised: mismatchingDnskeyRrsigData.serialise(),
      });
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [tldDnskey.record, mismatchingDnskeyRrsig]),
        [tldDs.data],
        new Date(),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });

    test('Expired RRSig for matching DNSKEY should be BOGUS', () => {
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [tldDnskey.record, tldDnskeyRrsig.record]),
        [tldDs.data],
        addSeconds(tldDnskeyRrsig.data.signatureExpiry, 1),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });

    test('DNSKEY should be BOGUS if it is not a ZSK', () => {
      const nonZskDnskeyData = new DnskeyData(
        tldDnskey.data.publicKey,
        tldDnskey.data.protocol,
        tldDnskey.data.algorithm,
        { ...tldDnskey.data.flags, zoneKey: false },
      );
      const nonZskDnskeyRecord = copyDnssecRecordData(tldDnskey, nonZskDnskeyData);
      const rrsig = tldSigner.generateRrsig(
        RRSet.init(TLD_DNSKEY_QUESTION, [nonZskDnskeyRecord.record]),
        nonZskDnskeyData.calculateKeyTag(),
        tldDnskeyRrsig.data.signatureExpiry,
        tldDnskeyRrsig.data.signatureInception,
      );
      const nonZskDs = rootSigner.generateDs(
        nonZskDnskeyRecord,
        RECORD_TLD,
        tldDs.record.ttl,
        tldDs.data.digestType,
      );
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [nonZskDnskeyRecord.record, rrsig.record]),
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
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [tldDnskey.record, tldDnskeyRrsig.record]),
        [tldDs.data],
        new Date(),
      );

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      expect(zone.name).toEqual(RECORD_TLD);
      expect(zone.dnskeys).toHaveLength(1);
      expect(zone.dnskeys[0].record).toEqual(tldDnskey.record);
    });

    test('Additional DNSKEYs should also be stored if a valid ZSK is found', async () => {
      const newApexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA1, tldSigner.zoneName);
      const nonZskDnskey = newApexSigner.generateDnskey(tldDnskey.record.ttl, { zoneKey: false });
      const newRrsig = tldSigner.generateRrsig(
        RRSet.init(TLD_DNSKEY_QUESTION, [tldDnskey.record, nonZskDnskey.record]),
        tldDnskey.data.calculateKeyTag(),
        tldDnskeyRrsig.data.signatureExpiry,
        tldDnskeyRrsig.data.signatureInception,
      );

      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [
          tldDnskey.record,
          nonZskDnskey.record,
          newRrsig.record,
        ]),
        [tldDs.data],
        new Date(),
      );

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      const dnskeyTags = zone.dnskeys.map((k) => k.data.calculateKeyTag());
      expect(dnskeyTags).toContainAllValues([
        tldDnskey.data.calculateKeyTag(),
        nonZskDnskey.data.calculateKeyTag(),
      ]);
    });
  });

  describe('initRoot', () => {
    test('Dot should be used as zone name', () => {
      const dnskeyMessage = new Message({ rcode: RCode.NoError }, [
        rootDnskey.record,
        rootDnskeyRrsig.record,
      ]);

      const result = Zone.initRoot(dnskeyMessage, [rootDs.data], new Date());

      expect(result).toMatchObject<SuccessfulResult<Zone>>({
        status: SecurityStatus.SECURE,
        result: expect.objectContaining({ name: '.' }),
      });
    });

    test('DNSKEY response message should be used', () => {
      const dnskeyMessage = new Message({ rcode: RCode.NoError }, [
        rootDnskey.record,
        rootDnskeyRrsig.record,
      ]);

      const result = Zone.initRoot(dnskeyMessage, [rootDs.data], new Date());

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      const dnskeyTags = zone.dnskeys.map((k) => k.data.calculateKeyTag());
      expect(dnskeyTags).toEqual([rootDnskey.data.calculateKeyTag()]);
    });

    test('Trust anchors should be used as DS set', () => {
      const dnskeyMessage = new Message({ rcode: RCode.NoError }, [
        rootDnskey.record,
        rootDnskeyRrsig.record,
      ]);

      const result = Zone.initRoot(
        dnskeyMessage,
        [
          tldDs.data, // Invalid
        ],
        new Date(),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No DNSKEY matched specified DS(s)'],
      });
    });

    test('Invalid zone should be BOGUS', () => {
      const dnskeyMessage = new Message({ rcode: RCode.NoError }, [
        rootDnskey.record,
        rootDnskeyRrsig.record,
      ]);

      const result = Zone.initRoot(
        dnskeyMessage,
        [rootDs.data],
        addSeconds(rootDnskeyRrsig.data.signatureExpiry, 1),
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });
  });

  describe('initChild', () => {
    let rootZone: Zone;
    let tldDnskeyMessage: Message;
    let tldDsRrsig: RrsigRecord;
    let tldDsMessage: Message;
    beforeAll(() => {
      rootZone = rootSigner.generateZone(addSeconds(new Date(), 60));

      tldDnskeyMessage = new Message({ rcode: RCode.NoError }, [
        tldDnskey.record,
        tldDnskeyRrsig.record,
      ]);

      tldDsRrsig = rootSigner.generateRrsig(
        RRSet.init({ ...TLD_DNSKEY_QUESTION, type: DnssecRecordType.DS }, [tldDs.record]),
        rootDnskey.data.calculateKeyTag(),
        addSeconds(new Date(), 60),
      );
      tldDsMessage = new Message({ rcode: RCode.NoError }, [tldDs.record, tldDsRrsig.record]);
    });

    describe('Zone name', () => {
      test('Directly-descending name should be supported', () => {
        const result = rootZone.initChild(RECORD_TLD, tldDnskeyMessage, tldDsMessage, new Date());

        expect(result).toMatchObject<SuccessfulResult<Zone>>({
          status: SecurityStatus.SECURE,
          result: expect.objectContaining({ name: RECORD_TLD }),
        });
      });

      test('Indirectly-descending name should be supported', async () => {
        const apexSigner = await ZoneSigner.generate(tldSigner.algorithm, RECORD.name);
        const apexDnskey = apexSigner.generateDnskey(42);
        const apexDnskeyRrsig = apexSigner.generateRrsig(
          RRSet.init({ ...QUESTION, type: DnssecRecordType.DNSKEY }, [apexDnskey.record]),
          apexDnskey.data.calculateKeyTag(),
          addSeconds(new Date(), 60),
        );
        const dnskeyMessage = new Message({ rcode: RCode.NoError }, [
          apexDnskey.record,
          apexDnskeyRrsig.record,
        ]);
        const apexDs = rootSigner.generateDs(apexDnskey, RECORD.name, 42);
        const apexDsRrsig = rootSigner.generateRrsig(
          RRSet.init({ ...QUESTION, type: DnssecRecordType.DS }, [apexDs.record]),
          rootDnskey.data.calculateKeyTag(),
          addSeconds(new Date(), 60),
        );
        const dsMessage = new Message({ rcode: RCode.NoError }, [
          apexDs.record,
          apexDsRrsig.record,
        ]);

        const result = rootZone.initChild(RECORD.name, dnskeyMessage, dsMessage, new Date());

        expect(result).toMatchObject<SuccessfulResult<Zone>>({
          status: SecurityStatus.SECURE,
          result: expect.objectContaining({ name: RECORD.name }),
        });
      });
    });

    test('DNSKEY response message should be used', () => {
      const result = rootZone.initChild(RECORD_TLD, tldDnskeyMessage, tldDsMessage, new Date());

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      expect(zone.dnskeys.map((k) => k.data.calculateKeyTag())).toEqual([
        tldDnskey.data.calculateKeyTag(),
      ]);
    });

    describe('DS', () => {
      test('DS message with rcode other than NOERROR should be BOGUS', () => {
        const invalidDsMessage = new Message(
          { ...tldDsMessage.header, rcode: 1 },
          tldDsMessage.answers,
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          invalidDsMessage,
          new Date(),
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.BOGUS,
          reasonChain: [
            `Expected DS rcode to be NOERROR (0; got ${invalidDsMessage.header.rcode})`,
          ],
        });
      });

      test('Malformed DS data should be BOGUS', () => {
        const malformedDsRecord = tldDs.record.shallowCopy({
          dataSerialised: Buffer.allocUnsafe(2),
        });
        const dsRrsig = rootSigner.generateRrsig(
          RRSet.init({ ...TLD_DNSKEY_QUESTION, type: DnssecRecordType.DS }, [malformedDsRecord]),
          rootDnskey.data.calculateKeyTag(),
          addSeconds(new Date(), 60),
        );
        const invalidDsMessage = new Message(tldDnskeyMessage.header, [
          malformedDsRecord,
          dsRrsig.record,
        ]);

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          invalidDsMessage,
          new Date(),
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.BOGUS,
          reasonChain: ['Found malformed DS rdata'],
        });
      });

      test('Expired DS should be BOGUS', () => {
        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          tldDsMessage,
          addSeconds(tldDsRrsig.data.signatureExpiry, 1),
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.BOGUS,
          reasonChain: ['Could not find at least one valid DS record'],
        });
      });

      test('DS not signed by parent zone should be BOGUS', async () => {
        const invalidDsRrsig = rootSigner.generateRrsig(
          RRSet.init({ ...TLD_DNSKEY_QUESTION, type: DnssecRecordType.DS }, [tldDs.record]),
          tldDnskey.data.calculateKeyTag() + 1, // This is what makes it invalid
          addSeconds(new Date(), 60),
        );
        const invaliDsMessage = new Message(tldDsMessage.header, [
          tldDs.record,
          invalidDsRrsig.record,
        ]);

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          invaliDsMessage,
          new Date(),
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.BOGUS,
          reasonChain: ['Could not find at least one valid DS record'],
        });
      });
    });
  });

  describe('verifyRrset', () => {
    const STUB_QUESTION = { ...QUESTION, name: '.' };
    const STUB_RRSET = RRSet.init(STUB_QUESTION, [RECORD.shallowCopy({ name: '.' })]);

    test('Invalid SignedRRset should be refused as BOGUS', () => {
      const zone = rootSigner.generateZone(addSeconds(new Date(), 60));
      const rrsig = rootSigner.generateRrsig(
        STUB_RRSET,
        zone.dnskeys[0].data.calculateKeyTag(),
        addSeconds(new Date(), 60),
      );
      const signedRrset = SignedRRSet.initFromRecords(STUB_QUESTION, [
        ...STUB_RRSET.records,
        rrsig.record,
      ]);

      expect(zone.verifyRrset(signedRrset, addSeconds(rrsig.data.signatureExpiry, 1))).toBeFalse();
    });

    test('ZSK should be allowed to sign RRset', () => {
      const zone = rootSigner.generateZone(addSeconds(new Date(), 60));
      const zskData = zone.dnskeys[0].data;
      expect(zskData.flags.zoneKey).toBeTrue();
      const rrsig = rootSigner.generateRrsig(
        STUB_RRSET,
        zskData.calculateKeyTag(),
        addSeconds(new Date(), 60),
      );
      const signedRrset = SignedRRSet.initFromRecords(STUB_QUESTION, [
        ...STUB_RRSET.records,
        rrsig.record,
      ]);

      expect(zone.verifyRrset(signedRrset, new Date())).toBeTrue();
    });

    test('Non-ZSK should be allowed to sign RRset', () => {
      const nonZsk = rootSigner.generateDnskey(42, { zoneKey: false });
      const zone = rootSigner.generateZone(addSeconds(new Date(), 60), {
        additionalDnskeys: [nonZsk.record],
      });
      const rrsig = rootSigner.generateRrsig(
        STUB_RRSET,
        nonZsk.data.calculateKeyTag(),
        addSeconds(new Date(), 60),
      );
      const signedRrset = SignedRRSet.initFromRecords(STUB_QUESTION, [
        ...STUB_RRSET.records,
        rrsig.record,
      ]);

      expect(zone.verifyRrset(signedRrset, new Date())).toBeTrue();
    });
  });
});
