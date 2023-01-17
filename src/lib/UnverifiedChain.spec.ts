import { jest } from '@jest/globals';
import { encode } from '@leichtgewicht/dns-packet';
import { addSeconds, subSeconds } from 'date-fns';

import { QUESTION, RECORD, RECORD_TLD, RRSET } from '../testUtils/dnsStubs.js';

import { ZoneSigner } from './testing/ZoneSigner.js';
import type { ZoneResponseSet } from './dnssecResponses.js';
import type { SignatureOptions } from './testing/SignatureOptions.js';
import { DnssecAlgorithm } from './DnssecAlgorithm.js';
import { Message } from './utils/dns/Message.js';
import { UnverifiedChain } from './UnverifiedChain.js';
import { DnssecRecordType } from './records/DnssecRecordType.js';
import { Question } from './utils/dns/Question.js';
import type {
  ChainVerificationResult,
  FailureResult,
  VerifiedRrSet,
} from './securityStatusResults.js';
import { SecurityStatus } from './SecurityStatus.js';
import type { DsData } from './records/DsData.js';
import { DatePeriod } from './DatePeriod.js';
import type { Resolver } from './Resolver.js';
import { DnsClass } from './utils/dns/ianaClasses.js';
import { getRcodeId, RCODE_IDS } from './utils/dns/ianaRcodes.js';
import type { DnskeyRecord } from './records/dnssecRecords.js';

const NOW = new Date();
const DATE_PERIOD = DatePeriod.init(NOW, addSeconds(NOW, 60));
const SIGNATURE_OPTIONS: SignatureOptions = {
  signatureExpiry: DATE_PERIOD.end,
  signatureInception: DATE_PERIOD.start,
};
const RESPONSE_GENERATION_OPTIONS = {
  dnskey: SIGNATURE_OPTIONS,
  ds: SIGNATURE_OPTIONS,
};

let rootSigner: ZoneSigner;
let tldSigner: ZoneSigner;
let apexSigner: ZoneSigner;
let rootResponses: ZoneResponseSet;
let tldResponses: ZoneResponseSet;
let apexResponses: ZoneResponseSet;
let queryResponse: Message;
let chainMessages: readonly Message[];

beforeAll(async () => {
  rootSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');
  rootResponses = rootSigner.generateZoneResponses(rootSigner, null, RESPONSE_GENERATION_OPTIONS);

  tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);
  tldResponses = tldSigner.generateZoneResponses(
    rootSigner,
    rootResponses.ds.data.keyTag,
    RESPONSE_GENERATION_OPTIONS,
  );

  apexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD.name);
  apexResponses = apexSigner.generateZoneResponses(
    tldSigner,
    tldResponses.ds.data.keyTag,
    RESPONSE_GENERATION_OPTIONS,
  );

  queryResponse = apexSigner.generateRrsig(
    RRSET,
    apexResponses.ds.data.keyTag,
    SIGNATURE_OPTIONS,
  ).message;

  chainMessages = [
    rootResponses.dnskey.message,
    tldResponses.dnskey.message,
    tldResponses.ds.message,
    apexResponses.dnskey.message,
    apexResponses.ds.message,
    queryResponse,
  ];
});

function filterMessagesOut(
  messages: readonly Message[],
  negativeQuestions: readonly Question[],
): readonly Message[] {
  return messages.filter(
    (message) => !negativeQuestions.some((question) => message.answersQuestion(question)),
  );
}

function replaceMessages(
  originalMessages: readonly Message[],
  newMessages: readonly Message[],
): readonly Message[] {
  const negativeQuestions = newMessages.flatMap((message) => message.questions);
  return [...filterMessagesOut(originalMessages, negativeQuestions), ...newMessages];
}

describe('retrieve', () => {
  const stubResolver = jest.fn<Resolver>();

  beforeEach(() => {
    // eslint-disable-next-line @typescript-eslint/require-await
    stubResolver.mockImplementation(async (question: Question) => {
      const martchingMessage = chainMessages.find((message) => message.answersQuestion(question));
      if (!martchingMessage) {
        throw new Error(`Could not find message that answers ${question.key}`);
      }
      return martchingMessage;
    });
  });

  afterEach(() => {
    stubResolver.mockReset();
  });

  test('Root DNSKEY should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, stubResolver);

    expect(chain.zoneMessageByKey[`./${DnssecRecordType.DNSKEY}`]).toStrictEqual(
      rootResponses.dnskey.message,
    );
  });

  test('Root DS should not be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, stubResolver);

    expect(chain.zoneMessageByKey).not.toHaveProperty([`./${DnssecRecordType.DS}`]);
    expect(stubResolver).not.toHaveBeenCalledWith(rootResponses.ds.record.makeQuestion());
  });

  test('Intermediate zone DNSKEYs should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, stubResolver);

    expect(chain.zoneMessageByKey[`${RECORD_TLD}/${DnssecRecordType.DNSKEY}`]).toStrictEqual(
      tldResponses.dnskey.message,
    );
    expect(chain.zoneMessageByKey[`${RECORD.name}/${DnssecRecordType.DNSKEY}`]).toStrictEqual(
      apexResponses.dnskey.message,
    );
  });

  test('Intermediate zone DSs should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, stubResolver);

    expect(chain.zoneMessageByKey[`${RECORD_TLD}/${DnssecRecordType.DS}`]).toStrictEqual(
      tldResponses.ds.message,
    );
    expect(chain.zoneMessageByKey[`${RECORD.name}/${DnssecRecordType.DS}`]).toStrictEqual(
      apexResponses.ds.message,
    );
  });

  test('Original query class should be used in zone queries', async () => {
    const stubMessage = rootResponses.dnskey.message;
    const differentQuestion = new Question(RECORD_TLD, DnssecRecordType.DS, DnsClass.IN + 1);

    // eslint-disable-next-line @typescript-eslint/require-await
    await UnverifiedChain.retrieve(differentQuestion, async (question) => {
      expect(question.classId).toStrictEqual(differentQuestion.classId);
      return stubMessage;
    });
  });

  test('Query response should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, stubResolver);

    expect(chain.response).toStrictEqual(queryResponse);
  });

  test('Question should be stored', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, stubResolver);

    expect(chain.query).toStrictEqual(QUESTION);
  });

  test('Returned message should be deserialised if given as a Buffer', async () => {
    const rcode = getRcodeId('YXRRSET');
    const messageSerialised = Buffer.from(
      encode({
        flags: rcode, // `rcode` field has no effect, so we have to pass it in the flags
      }),
    );
    // eslint-disable-next-line @typescript-eslint/require-await
    const resolver = async () => messageSerialised;

    const chain = await UnverifiedChain.retrieve(QUESTION, resolver);

    expect(chain.response.header.rcode).toStrictEqual(rcode);
    expect(chain.zoneMessageByKey[`./${DnssecRecordType.DNSKEY}`]!.header.rcode).toStrictEqual(
      rcode,
    );
  });

  test('Retrieval should error out with the first resolution error', async () => {
    const originalError = new Error('Whoops');
    stubResolver.mockRejectedValueOnce(originalError);

    await expect(UnverifiedChain.retrieve(QUESTION, stubResolver)).rejects.toBe(originalError);

    expect(stubResolver).toHaveBeenCalledTimes(1);
  });
});

describe('initFromMessages', () => {
  test('Question should be stored', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.query.equals(QUESTION)).toBeTrue();
  });

  test('Message without question should be ignored', () => {
    const unquestionableMessage = new Message({ rcode: RCODE_IDS.NOERROR }, [], []);
    const messages = [unquestionableMessage, ...chainMessages];

    expect(() => UnverifiedChain.initFromMessages(QUESTION, messages)).not.toThrow();
  });

  test('Irrelevant message should be filtered out', () => {
    const irrelevantQuestion = QUESTION.shallowCopy({ name: `not-${QUESTION.name}` });
    const irrelevantMessage = new Message({ rcode: RCODE_IDS.NOERROR }, [irrelevantQuestion], []);

    const chain = UnverifiedChain.initFromMessages(QUESTION, [irrelevantMessage, ...chainMessages]);

    expect(chain.zoneMessageByKey).not.toHaveProperty([irrelevantQuestion.key]);
  });

  test('./DS should not be stored if set', () => {
    const messages = [...chainMessages, rootResponses.ds.message];

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.zoneMessageByKey).not.toHaveProperty([`./${DnssecRecordType.DS}`]);
  });

  test('./DNSKEY should be stored if set', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.zoneMessageByKey).toHaveProperty(
      [`./${DnssecRecordType.DNSKEY}`],
      rootResponses.dnskey.message,
    );
  });

  test('Missing ./DNSKEY response should be undefined if unset', () => {
    const messages = filterMessagesOut(chainMessages, [rootResponses.dnskey.record.makeQuestion()]);

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.zoneMessageByKey).not.toHaveProperty([`./${DnssecRecordType.DNSKEY}`]);
  });

  test('Intermediate DS responses should be stored if set', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.zoneMessageByKey).toHaveProperty(
      [`${RECORD_TLD}/${DnssecRecordType.DS}`],
      tldResponses.ds.message,
    );
    expect(chain.zoneMessageByKey).toHaveProperty(
      [`${RECORD.name}/${DnssecRecordType.DS}`],
      apexResponses.ds.message,
    );
  });

  test('Intermediate DNSKEY responses should be stored if set', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.zoneMessageByKey).toHaveProperty(
      [`${RECORD_TLD}/${DnssecRecordType.DNSKEY}`],
      tldResponses.dnskey.message,
    );
    expect(chain.zoneMessageByKey).toHaveProperty(
      [`${RECORD.name}/${DnssecRecordType.DNSKEY}`],
      apexResponses.dnskey.message,
    );
  });

  test('Missing, intermediate DS responses should be undefined if unset', () => {
    const messages = filterMessagesOut(chainMessages, [tldResponses.ds.record.makeQuestion()]);

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.zoneMessageByKey).not.toHaveProperty([`${RECORD_TLD}/${DnssecRecordType.DS}`]);
  });

  test('Missing, intermediate DNSKEY responses should be undefined if unset', () => {
    const messages = filterMessagesOut(chainMessages, [tldResponses.dnskey.record.makeQuestion()]);

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.zoneMessageByKey).not.toHaveProperty([`${RECORD_TLD}/${DnssecRecordType.DNSKEY}`]);
  });

  test('Error should be thrown if no message would answer question', () => {
    const messages = filterMessagesOut(chainMessages, [QUESTION]);

    expect(() => UnverifiedChain.initFromMessages(QUESTION, messages)).toThrowWithMessage(
      Error,
      `At least one message must answer ${QUESTION.key}`,
    );
  });

  test('Response for question should be stored', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.response).toStrictEqual(queryResponse);
  });
});

describe('verify', () => {
  let trustAnchors: readonly DsData[];

  beforeAll(() => {
    trustAnchors = [rootResponses.ds.data];
  });

  describe('Zones', () => {
    test('Missing root DNSKEY response should be refused as INDETERMINATE', () => {
      const messages = filterMessagesOut(chainMessages, [
        rootResponses.dnskey.record.makeQuestion(),
      ]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<ChainVerificationResult>({
        status: SecurityStatus.INDETERMINATE,
        reasonChain: ['Cannot initialise root zone without a DNSKEY response'],
      });
    });

    test('Invalid root zone should be refused', () => {
      const invalidRootDnskey = rootSigner.generateDnskey({
        flags: { zoneKey: false }, // This is what's invalid
        ...SIGNATURE_OPTIONS,
      });
      const messages = replaceMessages(chainMessages, [invalidRootDnskey.message]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);
      const rootDs = rootSigner.generateDs(
        invalidRootDnskey,
        '.',
        invalidRootDnskey.data.calculateKeyTag(),
        SIGNATURE_OPTIONS,
      );

      const result = chain.verify(DATE_PERIOD, [rootDs.data]);

      expect(result).toStrictEqual<ChainVerificationResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['Got invalid DNSKEY for root zone', expect.anything()],
      });
    });

    test('Missing intermediate DNSKEY response should be refused as INDETERMINATE', () => {
      const messages = filterMessagesOut(chainMessages, [
        tldResponses.dnskey.record.makeQuestion(),
      ]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<ChainVerificationResult>({
        status: SecurityStatus.INDETERMINATE,
        reasonChain: [`Cannot verify zone ${RECORD_TLD} without a DNSKEY response`],
      });
    });

    test('Missing intermediate DS response should be refused as INDETERMINATE', () => {
      const messages = filterMessagesOut(chainMessages, [tldResponses.ds.record.makeQuestion()]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<ChainVerificationResult>({
        status: SecurityStatus.INDETERMINATE,
        reasonChain: [`Cannot verify zone ${RECORD_TLD} without a DS response`],
      });
    });

    test('Invalid intermediate zone should be refused', () => {
      const invalidTldDnskey = tldSigner.generateDnskey({
        flags: { zoneKey: false }, // This is what's invalid
        ...SIGNATURE_OPTIONS,
      });
      const tldDs = rootSigner.generateDs(
        invalidTldDnskey,
        RECORD_TLD,
        rootResponses.ds.data.keyTag,
        SIGNATURE_OPTIONS,
      );
      const messages = replaceMessages(chainMessages, [invalidTldDnskey.message, tldDs.message]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<ChainVerificationResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: [`Failed to verify zone ${RECORD_TLD}`, expect.anything()],
      });
    });

    test('Invalid apex zone should be refused', () => {
      const invalidApexDnskey = apexSigner.generateDnskey({
        flags: { zoneKey: false }, // This is what's invalid
        ...SIGNATURE_OPTIONS,
      });
      const apexDs = tldSigner.generateDs(
        invalidApexDnskey,
        RECORD.name,
        tldResponses.ds.data.keyTag,
        SIGNATURE_OPTIONS,
      );
      const messages = replaceMessages(chainMessages, [invalidApexDnskey.message, apexDs.message]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<ChainVerificationResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: [`Failed to verify zone ${RECORD.name}`, expect.anything()],
      });
    });
  });

  describe('Trust anchors', () => {
    let dsDataSpy: jest.SpiedFunction<any>;

    beforeEach(() => {
      dsDataSpy = jest.spyOn(rootResponses.ds.data, 'verifyDnskey') as any;
      dsDataSpy.mockReset();
    });

    afterAll(() => {
      dsDataSpy.mockRestore();
    });

    test('Specified trust anchor should be used to verify root DNSKEY', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

      chain.verify(DATE_PERIOD, trustAnchors);

      expect(dsDataSpy).toHaveBeenCalledTimes(1);
      expect(dsDataSpy).toHaveBeenCalledWith(
        expect.toSatisfy<DnskeyRecord>(
          (dnskey) => dnskey.data.keyTag === rootResponses.dnskey.data.calculateKeyTag(),
        ),
      );
    });
  });

  describe('Validity period', () => {
    test('Date period should overlap with that of chain', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);
      const period = DatePeriod.init(
        subSeconds(SIGNATURE_OPTIONS.signatureInception, 60),
        subSeconds(SIGNATURE_OPTIONS.signatureExpiry, 60),
      );

      const result = chain.verify(period, trustAnchors);

      expect(result.status).toStrictEqual(SecurityStatus.SECURE);
    });

    test('Date outside validity period should be refused', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);
      const period = DatePeriod.init(
        subSeconds(SIGNATURE_OPTIONS.signatureInception, 90),
        subSeconds(SIGNATURE_OPTIONS.signatureInception, 60),
      );

      const result = chain.verify(period, trustAnchors);

      expect(result.status).toStrictEqual(SecurityStatus.BOGUS);
    });
  });

  describe('Query response', () => {
    test('RRset signed by indirect ancestor should be allowed', () => {
      const newQueryResponse = tldSigner.generateRrsig(
        RRSET,
        tldResponses.ds.data.keyTag,
        SIGNATURE_OPTIONS,
      ).message;
      const messagesWithoutApexZone = filterMessagesOut(chainMessages, [
        apexResponses.dnskey.record.makeQuestion(),
        apexResponses.ds.record.makeQuestion(),
      ]);
      const chain = UnverifiedChain.initFromMessages(
        QUESTION,
        replaceMessages(messagesWithoutApexZone, [newQueryResponse]),
      );

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<VerifiedRrSet>({
        status: SecurityStatus.SECURE,
        result: RRSET,
      });
    });

    test('Missing RRSIG for query response should be refused', () => {
      const response = new Message({ rcode: RCODE_IDS.NOERROR }, [QUESTION], [RECORD]);
      const messages = replaceMessages(chainMessages, [response]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['Query response does not have a valid signature'],
      });
    });

    test('Invalid RRSIG for query response should be refused', () => {
      const expiredQueryResponse = apexSigner.generateRrsig(RRSET, apexResponses.ds.data.keyTag, {
        signatureExpiry: SIGNATURE_OPTIONS.signatureInception,
      }).message;
      const messages = replaceMessages(chainMessages, [expiredQueryResponse]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);
      const date = addSeconds(SIGNATURE_OPTIONS.signatureInception, 1);

      const result = chain.verify(DatePeriod.init(date, date), trustAnchors);

      expect(result).toStrictEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['Query response does not have a valid signature'],
      });
    });

    test('RRset should be returned if chain is valid', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

      const result = chain.verify(DATE_PERIOD, trustAnchors);

      expect(result).toStrictEqual<VerifiedRrSet>({
        status: SecurityStatus.SECURE,
        result: RRSET,
      });
    });
  });
});
