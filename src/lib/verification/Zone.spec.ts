import { addSeconds, subSeconds } from 'date-fns';

import { SignatureGenerationOptions, ZoneSigner } from '../signing/ZoneSigner';
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
import { copyDnssecRecordData } from '../../testUtils/dnssec/records';
import { Question } from '../dns/Question';
import { DNSClass } from '../dns/DNSClass';
import { DnssecRecordType } from '../DnssecRecordType';
import { RCode } from '../dns/RCode';
import { SignedRRSet } from './SignedRRSet';
import { DatePeriod } from './DatePeriod';

const NOW = new Date();
const VALIDITY_PERIOD = DatePeriod.init(subSeconds(NOW, 1), addSeconds(NOW, 1));
const SIGNATURE_OPTIONS: SignatureGenerationOptions = {
  signatureExpiry: VALIDITY_PERIOD.end,
  signatureInception: VALIDITY_PERIOD.start,
};

describe('Zone', () => {
  const TLD_DNSKEY_QUESTION = new Question(RECORD_TLD, DnssecRecordType.DNSKEY, DNSClass.IN);

  let rootSigner: ZoneSigner;
  let rootDnskey: DnskeyRecord;
  let rootDnskeyRrsig: RrsigRecord;
  let rootDs: DsRecord;
  beforeAll(async () => {
    rootSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');

    rootDnskey = rootSigner.generateDnskey({ flags: { zoneKey: true } });
    const rootDnskeyRrset = RRSet.init(new Question('.', DnssecRecordType.DNSKEY, DNSClass.IN), [
      rootDnskey.record,
    ]);
    rootDnskeyRrsig = rootSigner.generateRrsig(
      rootDnskeyRrset,
      rootDnskey.data.calculateKeyTag(),
      SIGNATURE_OPTIONS,
    );

    rootDs = rootSigner.generateDs(rootDnskey, '.');
  });

  let tldSigner: ZoneSigner;
  let tldDnskey: DnskeyRecord;
  let tldDnskeyRrsig: RrsigRecord;
  let tldDs: DsRecord;
  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);

    tldDnskey = tldSigner.generateDnskey();
    tldDnskeyRrsig = tldSigner.generateRrsig(
      RRSet.init(TLD_DNSKEY_QUESTION, [tldDnskey.record]),
      tldDnskey.data.calculateKeyTag(),
      SIGNATURE_OPTIONS,
    );

    tldDs = rootSigner.generateDs(tldDnskey, RECORD_TLD);
  });

  describe('init', () => {
    test('Message with rcode other than NOERROR should be BOGUS', () => {
      const rcode = 1;
      const dnskeyMessage = new Message({ rcode }, [], [tldDnskey.record, tldDnskeyRrsig.record]);

      const result = Zone.init(RECORD_TLD, dnskeyMessage, [tldDs.data], VALIDITY_PERIOD);

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
        SIGNATURE_OPTIONS,
      );
      const dnskeyMessage = new Message(
        { rcode: RCode.NoError },
        [],
        [malformedDnskey, newRrsig.record],
      );

      const result = Zone.init(RECORD_TLD, dnskeyMessage, [tldDs.data], VALIDITY_PERIOD);

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
        new Message({ rcode: RCode.NoError }, [], [tldDnskey.record, tldDnskeyRrsig.record]),
        [mismatchingDsData],
        VALIDITY_PERIOD,
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
        new Message({ rcode: RCode.NoError }, [], [tldDnskey.record, mismatchingDnskeyRrsig]),
        [tldDs.data],
        VALIDITY_PERIOD,
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
        new Message({ rcode: RCode.NoError }, [], [tldDnskey.record, mismatchingDnskeyRrsig]),
        [tldDs.data],
        VALIDITY_PERIOD,
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid RRSig was found'],
      });
    });

    test('Expired RRSig for matching DNSKEY should be BOGUS', () => {
      const invalidPeriod = DatePeriod.init(
        addSeconds(tldDnskeyRrsig.data.signatureExpiry, 1),
        addSeconds(tldDnskeyRrsig.data.signatureExpiry, 2),
      );

      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [], [tldDnskey.record, tldDnskeyRrsig.record]),
        [tldDs.data],
        invalidPeriod,
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
        SIGNATURE_OPTIONS,
      );
      const nonZskDs = rootSigner.generateDs(nonZskDnskeyRecord, RECORD_TLD, {
        digestType: tldDs.data.digestType,
      });
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [], [nonZskDnskeyRecord.record, rrsig.record]),
        [nonZskDs.data],
        VALIDITY_PERIOD,
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No DNSKEY matched specified DS(s)'],
      });
    });

    test('Zone should be initialised if ZSK is found', () => {
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCode.NoError }, [], [tldDnskey.record, tldDnskeyRrsig.record]),
        [tldDs.data],
        VALIDITY_PERIOD,
      );

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      expect(zone.name).toEqual(RECORD_TLD);
      expect(zone.dnskeys).toHaveLength(1);
      expect(zone.dnskeys[0].record).toEqual(tldDnskey.record);
    });

    test('Additional DNSKEYs should also be stored if a valid ZSK is found', async () => {
      const newApexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA1, tldSigner.zoneName);
      const nonZskDnskey = newApexSigner.generateDnskey({ flags: { zoneKey: false } });
      const newRrsig = tldSigner.generateRrsig(
        RRSet.init(TLD_DNSKEY_QUESTION, [tldDnskey.record, nonZskDnskey.record]),
        tldDnskey.data.calculateKeyTag(),
        SIGNATURE_OPTIONS,
      );

      const result = Zone.init(
        RECORD_TLD,
        new Message(
          { rcode: RCode.NoError },
          [],
          [tldDnskey.record, nonZskDnskey.record, newRrsig.record],
        ),
        [tldDs.data],
        VALIDITY_PERIOD,
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
      const dnskeyMessage = new Message(
        { rcode: RCode.NoError },
        [],
        [rootDnskey.record, rootDnskeyRrsig.record],
      );

      const result = Zone.initRoot(dnskeyMessage, [rootDs.data], VALIDITY_PERIOD);

      expect(result).toMatchObject<SuccessfulResult<Zone>>({
        status: SecurityStatus.SECURE,
        result: expect.objectContaining({ name: '.' }),
      });
    });

    test('DNSKEY response message should be used', () => {
      const dnskeyMessage = new Message(
        { rcode: RCode.NoError },
        [],
        [rootDnskey.record, rootDnskeyRrsig.record],
      );

      const result = Zone.initRoot(dnskeyMessage, [rootDs.data], VALIDITY_PERIOD);

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      const dnskeyTags = zone.dnskeys.map((k) => k.data.calculateKeyTag());
      expect(dnskeyTags).toEqual([rootDnskey.data.calculateKeyTag()]);
    });

    test('Trust anchors should be used as DS set', () => {
      const dnskeyMessage = new Message(
        { rcode: RCode.NoError },
        [],
        [rootDnskey.record, rootDnskeyRrsig.record],
      );

      const result = Zone.initRoot(
        dnskeyMessage,
        [
          tldDs.data, // Invalid
        ],
        VALIDITY_PERIOD,
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No DNSKEY matched specified DS(s)'],
      });
    });

    test('Invalid zone should be BOGUS', () => {
      const dnskeyMessage = new Message(
        { rcode: RCode.NoError },
        [],
        [rootDnskey.record, rootDnskeyRrsig.record],
      );
      const invalidPeriod = DatePeriod.init(
        addSeconds(rootDnskeyRrsig.data.signatureExpiry, 1),
        addSeconds(rootDnskeyRrsig.data.signatureExpiry, 2),
      );

      const result = Zone.initRoot(dnskeyMessage, [rootDs.data], invalidPeriod);

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
      rootZone = rootSigner.generateZone(addSeconds(NOW, 60));

      tldDnskeyMessage = new Message(
        { rcode: RCode.NoError },
        [],
        [tldDnskey.record, tldDnskeyRrsig.record],
      );

      tldDsRrsig = rootSigner.generateRrsig(
        RRSet.init(TLD_DNSKEY_QUESTION.shallowCopy({ type: DnssecRecordType.DS }), [tldDs.record]),
        rootDnskey.data.calculateKeyTag(),
        SIGNATURE_OPTIONS,
      );
      tldDsMessage = new Message({ rcode: RCode.NoError }, [], [tldDs.record, tldDsRrsig.record]);
    });

    describe('Zone name', () => {
      test('Directly-descending name should be supported', () => {
        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          tldDsMessage,
          VALIDITY_PERIOD,
        );

        expect(result).toMatchObject<SuccessfulResult<Zone>>({
          status: SecurityStatus.SECURE,
          result: expect.objectContaining({ name: RECORD_TLD }),
        });
      });

      test('Indirectly-descending name should be supported', async () => {
        const apexSigner = await ZoneSigner.generate(tldSigner.algorithm, RECORD.name);
        const apexDnskey = apexSigner.generateDnskey();
        const apexDnskeyRrsig = apexSigner.generateRrsig(
          RRSet.init(QUESTION.shallowCopy({ type: DnssecRecordType.DNSKEY }), [apexDnskey.record]),
          apexDnskey.data.calculateKeyTag(),
          SIGNATURE_OPTIONS,
        );
        const dnskeyMessage = new Message(
          { rcode: RCode.NoError },
          [],
          [apexDnskey.record, apexDnskeyRrsig.record],
        );
        const apexDs = rootSigner.generateDs(apexDnskey, RECORD.name);
        const apexDsRrsig = rootSigner.generateRrsig(
          RRSet.init(QUESTION.shallowCopy({ type: DnssecRecordType.DS }), [apexDs.record]),
          rootDnskey.data.calculateKeyTag(),
          SIGNATURE_OPTIONS,
        );
        const dsMessage = new Message(
          { rcode: RCode.NoError },
          [],
          [apexDs.record, apexDsRrsig.record],
        );

        const result = rootZone.initChild(RECORD.name, dnskeyMessage, dsMessage, VALIDITY_PERIOD);

        expect(result).toMatchObject<SuccessfulResult<Zone>>({
          status: SecurityStatus.SECURE,
          result: expect.objectContaining({ name: RECORD.name }),
        });
      });
    });

    test('DNSKEY response message should be used', () => {
      const result = rootZone.initChild(
        RECORD_TLD,
        tldDnskeyMessage,
        tldDsMessage,
        VALIDITY_PERIOD,
      );

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      expect(zone.dnskeys.map((k) => k.data.calculateKeyTag())).toEqual([
        tldDnskey.data.calculateKeyTag(),
      ]);
    });

    describe('DS', () => {
      test('DS message with rcode other than NOERROR should be BOGUS', () => {
        const invalidDsMessage = new Message(
          {
            ...tldDsMessage.header,
            rcode: 1,
          },
          [],
          tldDsMessage.answers,
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          invalidDsMessage,
          VALIDITY_PERIOD,
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
          RRSet.init(TLD_DNSKEY_QUESTION.shallowCopy({ type: DnssecRecordType.DS }), [
            malformedDsRecord,
          ]),
          rootDnskey.data.calculateKeyTag(),
          SIGNATURE_OPTIONS,
        );
        const invalidDsMessage = new Message(
          tldDnskeyMessage.header,
          [],
          [malformedDsRecord, dsRrsig.record],
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          invalidDsMessage,
          VALIDITY_PERIOD,
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.BOGUS,
          reasonChain: ['Found malformed DS rdata'],
        });
      });

      test('Expired DS should be BOGUS', () => {
        const invalidPeriod = DatePeriod.init(
          addSeconds(tldDsRrsig.data.signatureExpiry, 1),
          addSeconds(tldDsRrsig.data.signatureExpiry, 2),
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          tldDsMessage,
          invalidPeriod,
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.BOGUS,
          reasonChain: ['Could not find at least one valid DS record'],
        });
      });

      test('DS not signed by parent zone should be BOGUS', async () => {
        const invalidDsRrsig = rootSigner.generateRrsig(
          RRSet.init(TLD_DNSKEY_QUESTION.shallowCopy({ type: DnssecRecordType.DS }), [
            tldDs.record,
          ]),
          tldDnskey.data.calculateKeyTag() + 1, // This is what makes it invalid
          SIGNATURE_OPTIONS,
        );
        const invaliDsMessage = new Message(
          tldDsMessage.header,
          [],
          [tldDs.record, invalidDsRrsig.record],
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskeyMessage,
          invaliDsMessage,
          VALIDITY_PERIOD,
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.BOGUS,
          reasonChain: ['Could not find at least one valid DS record'],
        });
      });
    });
  });

  describe('verifyRrset', () => {
    const STUB_QUESTION = QUESTION.shallowCopy({ name: '.' });
    const STUB_RRSET = RRSet.init(STUB_QUESTION, [RECORD.shallowCopy({ name: '.' })]);

    test('Invalid SignedRRset should be refused as BOGUS', () => {
      const zone = rootSigner.generateZone(addSeconds(NOW, 60));
      const rrsig = rootSigner.generateRrsig(
        STUB_RRSET,
        zone.dnskeys[0].data.calculateKeyTag(),
        SIGNATURE_OPTIONS,
      );
      const signedRrset = SignedRRSet.initFromRecords(STUB_QUESTION, [
        ...STUB_RRSET.records,
        rrsig.record,
      ]);
      const invalidPeriod = DatePeriod.init(
        addSeconds(rrsig.data.signatureExpiry, 1),
        addSeconds(rrsig.data.signatureExpiry, 2),
      );

      expect(zone.verifyRrset(signedRrset, invalidPeriod)).toBeFalse();
    });

    test('ZSK should be allowed to sign RRset', () => {
      const zone = rootSigner.generateZone(addSeconds(NOW, 60));
      const zskData = zone.dnskeys[0].data;
      expect(zskData.flags.zoneKey).toBeTrue();
      const rrsig = rootSigner.generateRrsig(
        STUB_RRSET,
        zskData.calculateKeyTag(),
        SIGNATURE_OPTIONS,
      );
      const signedRrset = SignedRRSet.initFromRecords(STUB_QUESTION, [
        ...STUB_RRSET.records,
        rrsig.record,
      ]);

      expect(zone.verifyRrset(signedRrset, VALIDITY_PERIOD)).toBeTrue();
    });

    test('Non-ZSK should be allowed to sign RRset', () => {
      const nonZsk = rootSigner.generateDnskey({ flags: { zoneKey: false } });
      const zone = rootSigner.generateZone(addSeconds(NOW, 60), {
        additionalDnskeys: [nonZsk.record],
      });
      const rrsig = rootSigner.generateRrsig(
        STUB_RRSET,
        nonZsk.data.calculateKeyTag(),
        SIGNATURE_OPTIONS,
      );
      const signedRrset = SignedRRSet.initFromRecords(STUB_QUESTION, [
        ...STUB_RRSET.records,
        rrsig.record,
      ]);

      expect(zone.verifyRrset(signedRrset, VALIDITY_PERIOD)).toBeTrue();
    });
  });
});
