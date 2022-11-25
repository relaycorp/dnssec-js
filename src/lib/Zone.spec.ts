import { addSeconds, subSeconds } from 'date-fns';

import type { SignatureGenerationOptions } from '../testUtils/dnssec/ZoneSigner';
import { ZoneSigner } from '../testUtils/dnssec/ZoneSigner';
import { QUESTION, RECORD, RECORD_TLD } from '../testUtils/dnsStubs';
import type { DnskeyResponse, DsResponse } from '../testUtils/dnssec/responses';

import { DnssecAlgorithm } from './DnssecAlgorithm';
import { Zone } from './Zone';
import { Message } from './dns/Message';
import { SecurityStatus } from './SecurityStatus';
import type { DsRecord } from './dnssecRecords';
import { DsData } from './rdata/DsData';
import { RRSet } from './dns/RRSet';
import { RrsigData } from './rdata/RrsigData';
import type { FailureResult, SuccessfulResult } from './results';
import { Question } from './dns/Question';
import { DnsClass } from './dns/ianaClasses';
import { DnssecRecordType } from './DnssecRecordType';
import { SignedRRSet } from './SignedRRSet';
import { DatePeriod } from './DatePeriod';
import type { Record } from './dns/Record';
import { RCODE_IDS } from './dns/ianaRcodes';

const NOW = new Date();
const VALIDITY_PERIOD = DatePeriod.init(subSeconds(NOW, 1), addSeconds(NOW, 1));
const SIGNATURE_OPTIONS: SignatureGenerationOptions = {
  signatureExpiry: VALIDITY_PERIOD.end,
  signatureInception: VALIDITY_PERIOD.start,
};

describe('Zone', () => {
  const TLD_DNSKEY_QUESTION = new Question(RECORD_TLD, DnssecRecordType.DNSKEY, DnsClass.IN);

  let rootSigner: ZoneSigner;
  let rootDnskey: DnskeyResponse;
  let rootDs: DsRecord;

  beforeAll(async () => {
    rootSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');

    const rootResponses = rootSigner.generateZoneResponses(rootSigner, null, {
      dnskey: SIGNATURE_OPTIONS,
      ds: SIGNATURE_OPTIONS,
    });
    rootDnskey = rootResponses.dnskey;
    rootDs = rootResponses.ds;
  });

  let tldSigner: ZoneSigner;
  let tldDnskey: DnskeyResponse;
  let tldDs: DsResponse;

  beforeAll(async () => {
    tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);

    const tldResponses = tldSigner.generateZoneResponses(rootSigner, rootDs.data.keyTag, {
      dnskey: SIGNATURE_OPTIONS,
      ds: SIGNATURE_OPTIONS,
    });
    tldDnskey = tldResponses.dnskey;
    tldDs = tldResponses.ds;
  });

  describe('init', () => {
    test('DNSKEY message with rcode other than NOERROR should be INSECURE', () => {
      const rcode = 1;
      const dnskeyMessage = new Message({ rcode }, [], [tldDnskey.record, tldDnskey.rrsig.record]);

      const result = Zone.init(RECORD_TLD, dnskeyMessage, [tldDs.data], VALIDITY_PERIOD);

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.INSECURE,
        reasonChain: [`Expected DNSKEY rcode to be NOERROR (0; got ${rcode})`],
      });
    });

    test('DNSKEY without matching DS should be BOGUS', () => {
      const mismatchingDsData = new DsData(
        tldDs.data.keyTag,
        tldDs.data.algorithm + 1,
        tldDs.data.digestType,
        tldDs.data.digest,
      );

      const result = Zone.init(RECORD_TLD, tldDnskey.message, [mismatchingDsData], VALIDITY_PERIOD);

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No DNSKEY matched specified DS(s)'],
      });
    });

    test('Valid RRSig for non-matching DNSKEY should be BOGUS', () => {
      const mismatchingDnskeyRrsigData = new RrsigData(
        tldDnskey.rrsig.data.type,
        tldDnskey.rrsig.data.algorithm + 1,
        tldDnskey.rrsig.data.labels,
        tldDnskey.rrsig.data.ttl,
        tldDnskey.rrsig.data.signatureExpiry,
        tldDnskey.rrsig.data.signatureInception,
        tldDnskey.rrsig.data.keyTag,
        tldDnskey.rrsig.data.signerName,
        tldDnskey.rrsig.data.signature,
      );
      const mismatchingDnskeyRrsig = tldDnskey.rrsig.record.shallowCopy({
        dataSerialised: mismatchingDnskeyRrsigData.serialise(),
      });
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCODE_IDS.NoError }, [], [tldDnskey.record, mismatchingDnskeyRrsig]),
        [tldDs.data],
        VALIDITY_PERIOD,
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid DNSKEY RRSig was found'],
      });
    });

    test('Invalid RRSig for matching DNSKEY should be BOGUS', () => {
      const mismatchingDnskeyRrsigData = new RrsigData(
        tldDnskey.rrsig.data.type,
        tldDnskey.rrsig.data.algorithm,
        tldDnskey.rrsig.data.labels,
        tldDnskey.rrsig.data.ttl,
        tldDnskey.rrsig.data.signatureExpiry,
        tldDnskey.rrsig.data.signatureInception,
        tldDnskey.rrsig.data.keyTag + 1,
        tldDnskey.rrsig.data.signerName,
        tldDnskey.rrsig.data.signature,
      );
      const mismatchingDnskeyRrsig = tldDnskey.rrsig.record.shallowCopy({
        dataSerialised: mismatchingDnskeyRrsigData.serialise(),
      });
      const result = Zone.init(
        RECORD_TLD,
        new Message({ rcode: RCODE_IDS.NoError }, [], [tldDnskey.record, mismatchingDnskeyRrsig]),
        [tldDs.data],
        VALIDITY_PERIOD,
      );

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid DNSKEY RRSig was found'],
      });
    });

    test('Expired RRSig for matching DNSKEY should be BOGUS', () => {
      const invalidPeriod = DatePeriod.init(
        addSeconds(tldDnskey.rrsig.data.signatureExpiry, 1),
        addSeconds(tldDnskey.rrsig.data.signatureExpiry, 2),
      );

      const result = Zone.init(RECORD_TLD, tldDnskey.message, [tldDs.data], invalidPeriod);

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid DNSKEY RRSig was found'],
      });
    });

    test('DNSKEY should be BOGUS if it is not a ZSK', () => {
      const nonZskDnskey = tldSigner.generateDnskey({
        flags: { zoneKey: false },
        ...SIGNATURE_OPTIONS,
      });
      const nonZskDs = rootSigner.generateDs(nonZskDnskey, RECORD_TLD, rootDs.data.keyTag, {
        digestType: tldDs.data.digestType,
      });
      const result = Zone.init(RECORD_TLD, nonZskDnskey.message, [nonZskDs.data], VALIDITY_PERIOD);

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No DNSKEY matched specified DS(s)'],
      });
    });

    test('Zone should be initialised if ZSK is found', () => {
      const result = Zone.init(RECORD_TLD, tldDnskey.message, [tldDs.data], VALIDITY_PERIOD);

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
          { rcode: RCODE_IDS.NoError },
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
      const result = Zone.initRoot(rootDnskey.message, [rootDs.data], VALIDITY_PERIOD);

      expect(result).toMatchObject<SuccessfulResult<Zone>>({
        status: SecurityStatus.SECURE,
        result: expect.objectContaining({ name: '.' }),
      });
    });

    test('DNSKEY response message should be used', () => {
      const result = Zone.initRoot(rootDnskey.message, [rootDs.data], VALIDITY_PERIOD);

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      const dnskeyTags = zone.dnskeys.map((k) => k.data.calculateKeyTag());
      expect(dnskeyTags).toEqual([rootDnskey.data.calculateKeyTag()]);
    });

    test('Trust anchors should be used as DS set', () => {
      const result = Zone.initRoot(
        rootDnskey.message,
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
      const invalidPeriod = DatePeriod.init(
        addSeconds(rootDnskey.rrsig.data.signatureExpiry, 1),
        addSeconds(rootDnskey.rrsig.data.signatureExpiry, 2),
      );

      const result = Zone.initRoot(rootDnskey.message, [rootDs.data], invalidPeriod);

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['No valid DNSKEY RRSig was found'],
      });
    });
  });

  describe('initChild', () => {
    let rootZone: Zone;

    beforeAll(() => {
      rootZone = generateRootZone();
    });

    describe('Zone name', () => {
      test('Directly-descending name should be supported', () => {
        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskey.message,
          tldDs.message,
          VALIDITY_PERIOD,
        );

        expect(result).toMatchObject<SuccessfulResult<Zone>>({
          status: SecurityStatus.SECURE,
          result: expect.objectContaining({ name: RECORD_TLD }),
        });
      });

      test('Indirectly-descending name should be supported', async () => {
        const apexSigner = await ZoneSigner.generate(tldSigner.algorithm, RECORD.name);
        const apexDnskey = apexSigner.generateDnskey(SIGNATURE_OPTIONS);
        const apexDs = rootSigner.generateDs(
          apexDnskey,
          RECORD.name,
          tldDs.data.keyTag,
          SIGNATURE_OPTIONS,
        );
        const apexDsRrsig = rootSigner.generateRrsig(
          RRSet.init(QUESTION.shallowCopy({ type: DnssecRecordType.DS }), [apexDs.record]),
          rootDnskey.data.calculateKeyTag(),
          SIGNATURE_OPTIONS,
        );
        const dsMessage = new Message(
          { rcode: RCODE_IDS.NoError },
          [],
          [apexDs.record, apexDsRrsig.record],
        );

        const result = rootZone.initChild(
          RECORD.name,
          apexDnskey.message,
          dsMessage,
          VALIDITY_PERIOD,
        );

        expect(result).toMatchObject<SuccessfulResult<Zone>>({
          status: SecurityStatus.SECURE,
          result: expect.objectContaining({ name: RECORD.name }),
        });
      });
    });

    test('DNSKEY response message should be used', () => {
      const result = rootZone.initChild(
        RECORD_TLD,
        tldDnskey.message,
        tldDs.message,
        VALIDITY_PERIOD,
      );

      expect(result.status).toEqual(SecurityStatus.SECURE);
      const zone = (result as SuccessfulResult<Zone>).result;
      expect(zone.dnskeys.map((k) => k.data.calculateKeyTag())).toEqual([
        tldDnskey.data.calculateKeyTag(),
      ]);
    });

    describe('DS', () => {
      test('DS message with rcode other than NOERROR should be INSECURE', () => {
        const invalidDsMessage = new Message(
          {
            ...tldDs.message.header,
            rcode: 1,
          },
          [],
          tldDs.message.answers,
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskey.message,
          invalidDsMessage,
          VALIDITY_PERIOD,
        );

        expect(result).toEqual<FailureResult>({
          status: SecurityStatus.INSECURE,

          reasonChain: [
            `Expected DS rcode to be NOERROR (0; got ${invalidDsMessage.header.rcode})`,
          ],
        });
      });

      test('Expired DS should be BOGUS', () => {
        const invalidPeriod = DatePeriod.init(
          addSeconds(tldDs.rrsig.data.signatureExpiry, 1),
          addSeconds(tldDs.rrsig.data.signatureExpiry, 2),
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskey.message,
          tldDs.message,
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
          tldDs.message.header,
          [],
          [tldDs.record, invalidDsRrsig.record],
        );

        const result = rootZone.initChild(
          RECORD_TLD,
          tldDnskey.message,
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

    test('Invalid SignedRRset should be refused', () => {
      const zone = generateRootZone();
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
      const zone = generateRootZone();
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
      const zone = generateRootZone([nonZsk.record]);
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

  function generateRootZone(additionalDnskeys: readonly Record[] = []): Zone {
    const { dnskey, ds } = rootSigner.generateZoneResponses(rootSigner, rootDs.data.keyTag, {
      dnskey: {
        additionalDnskeys,
        flags: { zoneKey: true },
        ...SIGNATURE_OPTIONS,
      },

      ds: SIGNATURE_OPTIONS,
    });
    const zoneResult = Zone.init(rootSigner.zoneName, dnskey.message, [ds.data], VALIDITY_PERIOD);
    if (zoneResult.status !== SecurityStatus.SECURE) {
      throw new Error(`Failed to generate zone: ${zoneResult.reasonChain.join(', ')}`);
    }
    return zoneResult.result;
  }
});
