import type {
  Answer as DPAnswer,
  Question as DPQuestion,
  TxtAnswer,
} from '@leichtgewicht/dns-packet';
import { encode } from '@leichtgewicht/dns-packet';

import {
  QUESTION,
  RECORD,
  RECORD_CLASS_STR,
  RECORD_DATA_TXT_DATA,
  RECORD_TYPE_STR,
} from '../../testUtils/dnsStubs';

import { Message } from './Message';
import type { DnsRecord } from './DnsRecord';
import { DnsClass } from './ianaClasses';
import { DnsError } from './DnsError';
import { getRcodeId, RCODE_IDS } from './ianaRcodes';

describe('Message', () => {
  describe('deserialise', () => {
    const DP_QUESTION: DPQuestion = {
      class: RECORD_CLASS_STR,
      name: QUESTION.name,
      type: RECORD_TYPE_STR,
    };
    const DP_ANSWER: DPAnswer = {
      type: RECORD_TYPE_STR as any,
      class: RECORD_CLASS_STR,
      name: RECORD.name,
      ttl: RECORD.ttl,
      data: RECORD_DATA_TXT_DATA,
    };

    describe('Header', () => {
      test('RCODE should be extracted', () => {
        const rcodeId = getRcodeId('SERVFAIL');
        const messageSerialised = encode({
          type: 'response',
          flags: rcodeId, // `rcode` field has no effect, so we have to pass it in the flags
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.header.rcode).toStrictEqual(rcodeId);
      });
    });

    describe('Question', () => {
      function serialiseMessage(
        questions: readonly DPQuestion[],
        questionCount: number,
      ): Uint8Array {
        const validSerialisation = encode({
          type: 'response',
          questions: questions as DPQuestion[],
        });
        const malformedSerialisation = Buffer.from(validSerialisation);
        malformedSerialisation.writeUInt16BE(questionCount, 4);
        return malformedSerialisation;
      }

      test('No question should be output if the message had none', () => {
        const serialisation = encode({
          type: 'response',
        });

        const message = Message.deserialise(serialisation);

        expect(message.questions).toHaveLength(0);
      });

      test('One question should be output if the message had one', () => {
        const serialisation = encode({
          type: 'response',
          questions: [DP_QUESTION],
        });

        const message = Message.deserialise(serialisation);

        expect(message.questions).toHaveLength(1);
        expect(message.questions[0].equals(QUESTION)).toBeTrue();
      });

      test('Multiple questions should be output if the message had multiple', () => {
        const additionalQuestion = QUESTION.shallowCopy({ name: `sub.${QUESTION.name}` });
        const serialisation = encode({
          type: 'response',
          questions: [DP_QUESTION, { ...DP_QUESTION, name: additionalQuestion.name }],
        });

        const message = Message.deserialise(serialisation);

        expect(message.questions).toHaveLength(2);
        expect(message.questions[1].equals(additionalQuestion)).toBeTrue();
      });

      test('Questions should be capped at the length prefix', () => {
        const serialisation = serialiseMessage([DP_QUESTION, DP_QUESTION], 1);

        const message = Message.deserialise(serialisation);

        expect(message.questions).toHaveLength(1);
        expect(message.questions[0].equals(QUESTION)).toBeTrue();
      });

      test('Serialisation should be regarded malformed if QCOUNT is too high', () => {
        const serialisation = serialiseMessage([DP_QUESTION], 2);

        expect(() => Message.deserialise(serialisation)).toThrowWithMessage(
          DnsError,
          'Message serialisation does not comply with RFC 1035 (Section 4)',
        );
      });
    });

    describe('Answer', () => {
      function serialiseMessage(answers: readonly DPAnswer[], answerCount: number): Uint8Array {
        const validSerialisation = encode({
          type: 'response',
          answers: answers as DPAnswer[],
        });
        const malformedSerialisation = Buffer.from(validSerialisation);
        malformedSerialisation.writeUInt16BE(answerCount, 6);
        return malformedSerialisation;
      }

      test('No answer should be output if the message had none', () => {
        const messageSerialised = encode({
          type: 'response',
          answers: [],
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.answers).toBeEmpty();
      });

      test('One answer should be output if the message had one', () => {
        const messageSerialised = encode({
          type: 'response',
          answers: [DP_ANSWER],
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.answers).toHaveLength(1);
        expect(message.answers[0]).toMatchObject<Partial<DnsRecord>>({
          name: RECORD.name,
          typeId: RECORD.typeId,
          classId: RECORD.classId,
          ttl: RECORD.ttl,
        });
        expect(Buffer.from(message.answers[0].dataSerialised)).toStrictEqual(RECORD.dataSerialised);
      });

      test('Multiple answers should be output if the message had multiple', () => {
        const record2: TxtAnswer = {
          data: RECORD_DATA_TXT_DATA,
          name: 'foo.example.com.',
          type: 'TXT',
          ttl: RECORD.ttl,
        };
        const messageSerialised = encode({
          type: 'response',
          answers: [DP_ANSWER, record2],
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.answers).toHaveLength(2);
        expect(message.answers[0]).toMatchObject<Partial<DnsRecord>>({
          name: RECORD.name,
          typeId: RECORD.typeId,
          classId: DnsClass.IN,
          ttl: RECORD.ttl,
        });
        expect(Buffer.from(message.answers[0].dataSerialised)).toStrictEqual(RECORD.dataSerialised);
        expect(message.answers[1]).toMatchObject<Partial<DnsRecord>>({
          name: record2.name,
          typeId: 16,
          classId: DnsClass.IN,
          ttl: record2.ttl,
        });
        expect(Buffer.from(message.answers[1].dataSerialised)).toStrictEqual(RECORD.dataSerialised);
      });

      test('Answers should be capped at the length prefix', () => {
        const serialisation = serialiseMessage([DP_ANSWER, DP_ANSWER], 1);

        const message = Message.deserialise(serialisation);

        expect(message.answers).toHaveLength(1);
      });

      test('Serialisation should be regarded malformed if ANCOUNT is too high', () => {
        const serialisation = serialiseMessage([DP_ANSWER], 2);

        expect(() => Message.deserialise(serialisation)).toThrowWithMessage(
          DnsError,
          'Message serialisation does not comply with RFC 1035 (Section 4)',
        );
      });
    });

    test('Empty serialisation should be regarded malformed', () => {
      const serialisation = Buffer.from([]);

      expect(() => Message.deserialise(serialisation)).toThrowWithMessage(
        DnsError,
        'Message serialisation does not comply with RFC 1035 (Section 4)',
      );
    });
  });
});

describe('answersQuestion', () => {
  test('True should be returned if message contains question', () => {
    const message = new Message({ rcode: RCODE_IDS.NOERROR }, [QUESTION], []);

    expect(message.answersQuestion(QUESTION)).toBeTrue();
  });

  test('False should be returned if message does not contain question', () => {
    const message = new Message({ rcode: RCODE_IDS.NOERROR }, [QUESTION], []);
    const differentQuestion = QUESTION.shallowCopy({ type: QUESTION.typeId + 1 });

    expect(message.answersQuestion(differentQuestion)).toBeFalse();
  });
});
