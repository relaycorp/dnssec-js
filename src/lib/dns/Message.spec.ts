import {
  Answer as DPAnswer,
  decode,
  encode,
  Question as DPQuestion,
  TxtAnswer,
  TxtData,
} from '@leichtgewicht/dns-packet';

import { Message } from './Message';
import { Record } from './Record';
import { DnsClass } from './ianaClasses';
import {
  QUESTION,
  RECORD,
  RECORD_CLASS_STR,
  RECORD_DATA_TXT_DATA,
  RECORD_TYPE_STR,
} from '../../testUtils/dnsStubs';
import { Header } from './Header';
import { DnsError } from './DnsError';
import { getRcodeId, RCODE_IDS } from './ianaRcodes';

const STUB_HEADER: Header = { rcode: RCODE_IDS.NoError };

describe('Message', () => {
  describe('serialise', () => {
    describe('Header', () => {
      test('Id should be set to 0', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).id).toEqual(0);
      });

      test('QR flag should be on (response message)', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_qr).toBeTrue();
      });

      test('OPCODE should be set to 0 (QUERY)', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).opcode).toEqual('QUERY');
      });

      test('AA flag should be off', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_aa).toBeFalse();
      });

      test('TC flag should be off', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_tc).toBeFalse();
      });

      test('RD flag should be off', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_rd).toBeFalse();
      });

      test('RA flag should be off', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_ra).toBeFalse();
      });

      test('Z flag should be off', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_z).toBeFalse();
      });

      test('RCODE should be honoured', () => {
        const rcode = 15;
        const message = new Message({ ...STUB_HEADER, rcode }, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).rcode).toEqual('RCODE_15');
      });
    });

    describe('Question', () => {
      test('No questions should be output if there are none', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).questions).toHaveLength(0);
      });

      test('One question should be output if there is one', () => {
        const message = new Message(STUB_HEADER, [QUESTION], []);

        const serialisation = message.serialise();

        const deserialisedQuestions = decode(serialisation).questions;
        expect(deserialisedQuestions).toHaveLength(1);
        expect(deserialisedQuestions![0]).toEqual({
          name: QUESTION.name.replace(/\.$/, ''),
          type: RECORD_TYPE_STR,
          class: RECORD_CLASS_STR,
        });
      });

      test('Multiple questions should be output if there are multiple', () => {
        const additionalQuestion = QUESTION.shallowCopy({ name: `sub.${QUESTION.name}` });
        const message = new Message(STUB_HEADER, [QUESTION, additionalQuestion], []);

        const serialisation = message.serialise();

        const deserialisedQuestions = decode(serialisation).questions;
        expect(deserialisedQuestions).toHaveLength(2);
        expect(deserialisedQuestions![1]).toEqual({
          name: additionalQuestion.name.replace(/\.$/, ''),
          type: RECORD_TYPE_STR,
          class: RECORD_CLASS_STR,
        });
      });
    });

    describe('Answer', () => {
      test('No records should be output if there are none', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers).toHaveLength(0);
      });

      test('One record should be output if there is one', () => {
        const message = new Message(STUB_HEADER, [], [RECORD]);

        const serialisation = message.serialise();

        const answers = decode(serialisation).answers;
        expect(answers).toHaveLength(1);
        expect(answers![0].name).toEqual(RECORD.name.replace(/\.$/, ''));
        expect(answers![0].type).toEqual(RECORD_TYPE_STR);
        expect(answers![0].class).toEqual('IN');
        expect(answers![0].ttl).toEqual(RECORD.ttl);
        expect(answers![0].data).toHaveLength(1);
        expect((answers![0].data as TxtData)[0]).toEqual(RECORD_DATA_TXT_DATA);
      });

      test('Multiple records should be output if there are multiple', () => {
        const answer2Rdata = Buffer.alloc(2);
        answer2Rdata.writeUInt8(1);
        answer2Rdata.writeUInt8(42, 1);
        const answer2 = RECORD.shallowCopy({ dataSerialised: answer2Rdata });
        const message = new Message(STUB_HEADER, [], [RECORD, answer2]);

        const serialisation = message.serialise();

        const answers = decode(serialisation).answers;
        expect(answers).toHaveLength(2);
        expect((answers![0].data as TxtData)[0]).toEqual(RECORD_DATA_TXT_DATA);
        expect((answers![1].data as TxtData)[0]).toEqual(answer2Rdata.subarray(1));
      });
    });

    describe('Authority', () => {
      test('There should be no authority records', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).authorities).toHaveLength(0);
      });
    });

    describe('Additional', () => {
      test('There should be no additional records', () => {
        const message = new Message(STUB_HEADER, [], []);

        const serialisation = message.serialise();

        expect(decode(serialisation).additionals).toHaveLength(0);
      });
    });
  });

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
        const rcodeName = 'ServFail';
        const messageSerialised = encode({
          type: 'response',
          rcode: rcodeName,
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.header.rcode).toEqual(getRcodeId(rcodeName));
      });
    });

    describe('Question', () => {
      test('No question should be output if the message had none', () => {
        const serialisation = new Message({ rcode: RCODE_IDS.NoError }, [], []).serialise();

        const message = Message.deserialise(serialisation);

        expect(message.questions).toHaveLength(0);
      });

      test('One question should be output if the message had one', () => {
        const serialisation = new Message({ rcode: RCODE_IDS.NoError }, [QUESTION], []).serialise();

        const message = Message.deserialise(serialisation);

        expect(message.questions).toHaveLength(1);
        expect(message.questions[0].equals(QUESTION)).toBeTrue();
      });

      test('Multiple questions should be output if the message had multiple', () => {
        const additionalQuestion = QUESTION.shallowCopy({ name: `sub.${QUESTION.name}` });
        const serialisation = new Message(
          { rcode: RCODE_IDS.NoError },
          [QUESTION, additionalQuestion],
          [],
        ).serialise();

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

      function serialiseMessage(
        questions: readonly DPQuestion[],
        questionCount: number,
      ): Uint8Array {
        const validSerialisation = encode({
          type: 'response',
          // tslint:disable-next-line:readonly-array
          questions: questions as DPQuestion[],
        });
        const malformedSerialisation = Buffer.from(validSerialisation);
        malformedSerialisation.writeUInt16BE(questionCount, 4);
        return malformedSerialisation;
      }
    });

    describe('Answer', () => {
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
        expect(message.answers[0]).toMatchObject<Partial<Record>>({
          name: RECORD.name,
          typeId: RECORD.typeId,
          class_: RECORD.class_,
          ttl: RECORD.ttl,
        });
        expect(Buffer.from(message.answers[0].dataSerialised)).toEqual(RECORD.dataSerialised);
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
        expect(message.answers[0]).toMatchObject<Partial<Record>>({
          name: RECORD.name,
          typeId: RECORD.typeId,
          class_: DnsClass.IN,
          ttl: RECORD.ttl,
        });
        expect(Buffer.from(message.answers[0].dataSerialised)).toEqual(RECORD.dataSerialised);
        expect(message.answers[1]).toMatchObject<Partial<Record>>({
          name: record2.name,
          typeId: 16,
          class_: DnsClass.IN,
          ttl: record2.ttl,
        });
        expect(Buffer.from(message.answers[1].dataSerialised)).toEqual(RECORD.dataSerialised);
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

      function serialiseMessage(answers: readonly DPAnswer[], answerCount: number): Uint8Array {
        const validSerialisation = encode({
          type: 'response',
          // tslint:disable-next-line:readonly-array
          answers: answers as DPAnswer[],
        });
        const malformedSerialisation = Buffer.from(validSerialisation);
        malformedSerialisation.writeUInt16BE(answerCount, 6);
        return malformedSerialisation;
      }
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
    const message = new Message({ rcode: RCODE_IDS.NoError }, [QUESTION], []);

    expect(message.answersQuestion(QUESTION)).toBeTrue();
  });

  test('False should be returned if message does not contain question', () => {
    const message = new Message({ rcode: RCODE_IDS.NoError }, [QUESTION], []);
    const differentQuestion = QUESTION.shallowCopy({ type: QUESTION.typeId + 1 });

    expect(message.answersQuestion(differentQuestion)).toBeFalse();
  });
});
