import { jest } from '@jest/globals';
import { encode } from '@leichtgewicht/dns-packet';

import { addSeconds, subSeconds } from 'date-fns';
import { SignatureGenerationOptions, ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { Message } from '../dns/Message';
import { QUESTION, RECORD, RECORD_TLD, RRSET } from '../../testUtils/dnsStubs';
import { ChainVerificationResult, UnverifiedChain, VerifiedChainResult } from './UnverifiedChain';
import { ZoneResponseSet } from '../signing/responses';
import { DnssecRecordType } from '../DnssecRecordType';
import { Question } from '../dns/Question';
import { FailureResult } from './results';
import { SecurityStatus } from './SecurityStatus';
import { DsData } from '../rdata/DsData';
import { IANA_TRUST_ANCHORS } from './IANA_TRUST_ANCHORS';
import { DatePeriod } from './DatePeriod';
import { Resolver } from './Resolver';
import { DnsClass } from '../dns/ianaClasses';
import { getRcodeId, RCODE_IDS } from '../dns/ianaRcodes';

const NOW = new Date();
const SIGNATURE_OPTIONS: SignatureGenerationOptions = {
  signatureExpiry: addSeconds(NOW, 60),
  signatureInception: NOW,
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

describe('retrieve', () => {
  const RESOLVER = jest.fn<Resolver>();
  beforeEach(() => {
    RESOLVER.mockImplementation(async (question: Question) => {
      const message = chainMessages.find((m) => m.answersQuestion(question));
      if (!message) {
        throw new Error(`Could not find message that answers ${question.key}`);
      }
      return message;
    });
  });
  afterEach(() => {
    RESOLVER.mockReset();
  });

  test('Root DNSKEY should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, RESOLVER);

    expect(chain.zoneMessageByKey[`./${DnssecRecordType.DNSKEY}`]).toEqual(
      rootResponses.dnskey.message,
    );
  });

  test('Root DS should not be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, RESOLVER);

    expect(chain.zoneMessageByKey).not.toHaveProperty([`./${DnssecRecordType.DS}`]);
    expect(RESOLVER).not.toBeCalledWith(rootResponses.ds.record.makeQuestion);
  });

  test('Intermediate zone DNSKEYs should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, RESOLVER);

    expect(chain.zoneMessageByKey[`${RECORD_TLD}/${DnssecRecordType.DNSKEY}`]).toEqual(
      tldResponses.dnskey.message,
    );
    expect(chain.zoneMessageByKey[`${RECORD.name}/${DnssecRecordType.DNSKEY}`]).toEqual(
      apexResponses.dnskey.message,
    );
  });

  test('Intermediate zone DSs should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, RESOLVER);

    expect(chain.zoneMessageByKey[`${RECORD_TLD}/${DnssecRecordType.DS}`]).toEqual(
      tldResponses.ds.message,
    );
    expect(chain.zoneMessageByKey[`${RECORD.name}/${DnssecRecordType.DS}`]).toEqual(
      apexResponses.ds.message,
    );
  });

  test('Original query class should be used in zone queries', async () => {
    const stubMessage = rootResponses.dnskey.message;
    const differentQuestion = new Question(RECORD_TLD, DnssecRecordType.DS, DnsClass.IN + 1);

    await UnverifiedChain.retrieve(differentQuestion, async (question) => {
      expect(question.class_).toEqual(differentQuestion.class_);
      return stubMessage;
    });
  });

  test('Query response should be retrieved', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, RESOLVER);

    expect(chain.response).toEqual(queryResponse);
  });

  test('Question should be stored', async () => {
    const chain = await UnverifiedChain.retrieve(QUESTION, RESOLVER);

    expect(chain.query).toEqual(QUESTION);
  });

  test('Returned message should be deserialised if given as a Buffer', async () => {
    const rcode = getRcodeId('YXRRSet');
    const messageSerialised = Buffer.from(
      encode({
        flags: rcode, // `rcode` field has no effect, so we have to pass it in the flags
      }),
    );
    const resolver = async () => messageSerialised;

    const chain = await UnverifiedChain.retrieve(QUESTION, resolver);

    expect(chain.response.header.rcode).toEqual(rcode);
    expect(chain.zoneMessageByKey[`./${DnssecRecordType.DNSKEY}`].header.rcode).toEqual(rcode);
  });
});

describe('initFromMessages', () => {
  test('Question should be stored', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.query.equals(QUESTION)).toBeTrue();
  });

  test('Message without question should be ignored', () => {
    const unquestionableMessage = new Message({ rcode: RCODE_IDS.NoError }, [], []);

    UnverifiedChain.initFromMessages(QUESTION, [unquestionableMessage, ...chainMessages]);
  });

  test('Irrelevant message should be filtered out', () => {
    const irrelevantQuestion = QUESTION.shallowCopy({ name: `not-${QUESTION.name}` });
    const irrelevantMessage = new Message({ rcode: RCODE_IDS.NoError }, [irrelevantQuestion], []);

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

    expect(chain.response).toEqual(queryResponse);
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

      const result = chain.verify({ trustAnchors });

      expect(result).toEqual<ChainVerificationResult>({
        status: SecurityStatus.INDETERMINATE,
        reasonChain: [`Cannot initialise root zone without a DNSKEY response`],
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

      const result = chain.verify({ trustAnchors: [rootDs.data] });

      expect(result).toEqual<ChainVerificationResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: [`Got invalid DNSKEY for root zone`, expect.anything()],
      });
    });

    test('Missing intermediate DNSKEY response should be refused as INDETERMINATE', () => {
      const messages = filterMessagesOut(chainMessages, [
        tldResponses.dnskey.record.makeQuestion(),
      ]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify({ trustAnchors });

      expect(result).toEqual<ChainVerificationResult>({
        status: SecurityStatus.INDETERMINATE,
        reasonChain: [`Cannot verify zone ${RECORD_TLD} without a DNSKEY response`],
      });
    });

    test('Missing intermediate DS response should be refused as INDETERMINATE', () => {
      const messages = filterMessagesOut(chainMessages, [tldResponses.ds.record.makeQuestion()]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

      const result = chain.verify({ trustAnchors });

      expect(result).toEqual<ChainVerificationResult>({
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

      const result = chain.verify({ trustAnchors });

      expect(result).toEqual<ChainVerificationResult>({
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

      const result = chain.verify({ trustAnchors });

      expect(result).toEqual<ChainVerificationResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: [`Failed to verify zone ${RECORD.name}`, expect.anything()],
      });
    });
  });

  describe('Trust anchors', () => {
    const ianaRootDsDataSpy = jest.spyOn(IANA_TRUST_ANCHORS[0], 'verifyDnskey');
    beforeEach(() => {
      ianaRootDsDataSpy.mockReset();
    });
    afterAll(() => {
      ianaRootDsDataSpy.mockRestore();
    });

    test('IANA trust anchors should be used by default', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

      chain.verify();

      expect(ianaRootDsDataSpy).toBeCalledWith(
        expect.toSatisfy((k) => k.data.keyTag === rootResponses.dnskey.data.calculateKeyTag()),
      );
    });

    test('Trust anchors should be customizable', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

      chain.verify({ trustAnchors });

      expect(ianaRootDsDataSpy).not.toBeCalled();
    });
  });

  describe('Validity period', () => {
    test('Single date should be within date period of chain', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

      const result = chain.verify({
        dateOrPeriod: SIGNATURE_OPTIONS.signatureInception,
        trustAnchors,
      });

      expect(result.status).toEqual(SecurityStatus.SECURE);
    });

    test('Date period should overlap with that of chain', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);
      const period = DatePeriod.init(
        subSeconds(SIGNATURE_OPTIONS.signatureInception, 60),
        subSeconds(SIGNATURE_OPTIONS.signatureExpiry, 60),
      );

      const result = chain.verify({ dateOrPeriod: period, trustAnchors });

      expect(result.status).toEqual(SecurityStatus.SECURE);
    });

    test('Date outside validity period should be refused', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);
      const date = subSeconds(SIGNATURE_OPTIONS.signatureInception, 1);

      const result = chain.verify({ dateOrPeriod: date, trustAnchors });

      expect(result.status).toEqual(SecurityStatus.BOGUS);
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

      const result = chain.verify({ trustAnchors });

      expect(result).toEqual<VerifiedChainResult>({
        status: SecurityStatus.SECURE,
        result: RRSET,
      });
    });

    test('Invalid signature for query response should be refused', () => {
      const expiredQueryResponse = apexSigner.generateRrsig(RRSET, apexResponses.ds.data.keyTag, {
        signatureExpiry: SIGNATURE_OPTIONS.signatureInception,
      }).message;
      const messages = replaceMessages(chainMessages, [expiredQueryResponse]);
      const chain = UnverifiedChain.initFromMessages(QUESTION, messages);
      const date = addSeconds(SIGNATURE_OPTIONS.signatureInception, 1);

      const result = chain.verify({ dateOrPeriod: date, trustAnchors });

      expect(result).toEqual<FailureResult>({
        status: SecurityStatus.BOGUS,
        reasonChain: ['Query response does not have a valid signature'],
      });
    });

    test('RRset should be returned if chain is valid', () => {
      const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

      const result = chain.verify({ trustAnchors });

      expect(result).toEqual<VerifiedChainResult>({
        status: SecurityStatus.SECURE,
        result: RRSET,
      });
    });
  });
});

function filterMessagesOut(
  messages: readonly Message[],
  negativeQuestions: readonly Question[],
): readonly Message[] {
  return messages.filter((m) => !negativeQuestions.some((q) => m.answersQuestion(q)));
}

function replaceMessages(
  originalMessages: readonly Message[],
  newMessages: readonly Message[],
): readonly Message[] {
  const negativeQuestions = newMessages.flatMap((m) => m.questions);
  return [...filterMessagesOut(originalMessages, negativeQuestions), ...newMessages];
}
