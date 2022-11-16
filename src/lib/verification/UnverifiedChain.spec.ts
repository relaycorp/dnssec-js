import { addSeconds } from 'date-fns';

import { SignatureGenerationOptions, ZoneSigner } from '../signing/ZoneSigner';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { Message } from '../dns/Message';
import { QUESTION, RECORD, RECORD_TLD, RRSET } from '../../testUtils/dnsStubs';
import { UnverifiedChain } from './UnverifiedChain';
import { Question } from '../dns/Question';
import { ZoneResponseSet } from '../signing/responses';
import { DnssecRecordType } from '../DnssecRecordType';
import { DNSClass } from '../dns/DNSClass';
import { RCode } from '../dns/RCode';

describe('initFromMessages', () => {
  const NOW = new Date();
  const SIGNATURE_OPTIONS: SignatureGenerationOptions = {
    signatureExpiry: addSeconds(NOW, 60),
    signatureInception: NOW,
  };
  const RESPONSE_GENERATION_OPTIONS = {
    dnskey: SIGNATURE_OPTIONS,
    ds: SIGNATURE_OPTIONS,
  };

  let rootResponses: ZoneResponseSet;
  let tldResponses: ZoneResponseSet;
  let apexResponses: ZoneResponseSet;
  let queryResponse: Message;
  let chainMessages: readonly Message[];
  beforeAll(async () => {
    const rootSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, '.');
    rootResponses = rootSigner.generateZoneResponses(rootSigner, RESPONSE_GENERATION_OPTIONS);

    const tldSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD_TLD);
    tldResponses = tldSigner.generateZoneResponses(rootSigner, RESPONSE_GENERATION_OPTIONS);

    const apexSigner = await ZoneSigner.generate(DnssecAlgorithm.RSASHA256, RECORD.name);
    apexResponses = apexSigner.generateZoneResponses(tldSigner, RESPONSE_GENERATION_OPTIONS);

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

  test('Question should be stored', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.question.equals(QUESTION)).toBeTrue();
  });

  test('Empty messages should be supported gracefully', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, []);

    expect(chain.messageByKey).toBeEmptyObject();
  });

  test('Message without question should be ignored', () => {
    const message = new Message({ rcode: RCode.NoError }, [], []);

    const chain = UnverifiedChain.initFromMessages(QUESTION, [message]);

    expect(chain.messageByKey).toBeEmptyObject();
  });

  test('Irrelevant message should be filtered out', () => {
    const irrelevantQuestion = QUESTION.shallowCopy({ name: `not-${QUESTION.name}` });
    const irrelevantMessage = new Message({ rcode: RCode.NoError }, [irrelevantQuestion], []);

    const chain = UnverifiedChain.initFromMessages(QUESTION, [irrelevantMessage, ...chainMessages]);

    expect(chain.messageByKey).not.toHaveProperty([irrelevantQuestion.key]);
  });

  test('./DS should not be stored if set', () => {
    const messages = [...chainMessages, rootResponses.ds.message];

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.messageByKey).not.toHaveProperty([`./${DnssecRecordType.DS}`]);
  });

  test('./DNSKEY should be stored if set', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.messageByKey).toHaveProperty(
      [`./${DnssecRecordType.DNSKEY}`],
      rootResponses.dnskey.message,
    );
  });

  test('Missing ./DNSKEY response should be undefined if unset', () => {
    const messages = filterMessagesOut(
      chainMessages,
      new Question('.', DnssecRecordType.DNSKEY, DNSClass.IN),
    );

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.messageByKey).not.toHaveProperty([`./${DnssecRecordType.DNSKEY}`]);
  });

  test('Intermediate DS responses should be stored if set', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.messageByKey).toHaveProperty(
      [`${RECORD_TLD}/${DnssecRecordType.DS}`],
      tldResponses.ds.message,
    );
    expect(chain.messageByKey).toHaveProperty(
      [`${RECORD.name}/${DnssecRecordType.DS}`],
      apexResponses.ds.message,
    );
  });

  test('Intermediate DNSKEY responses should be stored if set', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.messageByKey).toHaveProperty(
      [`${RECORD_TLD}/${DnssecRecordType.DNSKEY}`],
      tldResponses.dnskey.message,
    );
    expect(chain.messageByKey).toHaveProperty(
      [`${RECORD.name}/${DnssecRecordType.DNSKEY}`],
      apexResponses.dnskey.message,
    );
  });

  test('Missing, intermediate DS responses should be undefined if unset', () => {
    const messages = filterMessagesOut(
      chainMessages,
      new Question(RECORD_TLD, DnssecRecordType.DS, DNSClass.IN),
    );

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.messageByKey).not.toHaveProperty([`${RECORD_TLD}/${DnssecRecordType.DS}`]);
  });

  test('Missing, intermediate DNSKEY responses should be undefined if unset', () => {
    const messages = filterMessagesOut(
      chainMessages,
      new Question(RECORD_TLD, DnssecRecordType.DNSKEY, DNSClass.IN),
    );

    const chain = UnverifiedChain.initFromMessages(QUESTION, messages);

    expect(chain.messageByKey).not.toHaveProperty([`${RECORD_TLD}/${DnssecRecordType.DNSKEY}`]);
  });

  test('Response for question should be stored if set', () => {
    const chain = UnverifiedChain.initFromMessages(QUESTION, chainMessages);

    expect(chain.messageByKey).toHaveProperty([`${RECORD.name}/${RECORD.type}`], queryResponse);
  });

  function filterMessagesOut(
    messages: readonly Message[],
    negativeQuestion: Question,
  ): readonly Message[] {
    return messages.filter((m) => !m.answersQuestion(negativeQuestion));
  }
});

// describe('verify', () => {
//   describe('Zones', () => {
//     test.todo('Root DNSKEYs should be specified');
//
//     test.todo('Trust anchors should be honoured');
//
//     test.todo('Intermediate DSs should be specified');
//
//     test.todo('Intermediate DNSKEYs should be specified');
//
//     test.todo('Leaf DSs should be specified');
//
//     test.todo('Leaf DNSKEYs should be specified');
//   });
//
//   test.todo('At least a message should answer the question');
//
//   test.todo('Valid chain should be initialised');
// });
