import {
  Answer as DPAnswer,
  decode,
  encode,
  Question,
  TxtAnswer,
  TxtData,
} from '@leichtgewicht/dns-packet';

import { Message } from './Message';
import { MalformedMessage } from './MalformedMessage';
import { Record } from './Record';
import { DNSClass } from './DNSClass';
import {
  RECORD,
  RECORD_CLASS,
  RECORD_CLASS_STR,
  RECORD_DATA,
  RECORD_DATA_TXT_DATA,
  RECORD_NAME,
  RECORD_TTL,
  RECORD_TYPE,
  RECORD_TYPE_ID,
} from '../../testUtils/stubs';
import { Header } from './Header';
import { RCode } from './RCode';

const STUB_HEADER: Header = { rcode: RCode.NoError };

describe('Message', () => {
  describe('serialise', () => {
    describe('Header', () => {
      test('Id should be set to 0', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).id).toEqual(0);
      });

      test('QR flag should be on (response message)', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_qr).toBeTrue();
      });

      test('OPCODE should be set to 0 (QUERY)', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).opcode).toEqual('QUERY');
      });

      test('AA flag should be off', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_aa).toBeFalse();
      });

      test('TC flag should be off', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_tc).toBeFalse();
      });

      test('RD flag should be off', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_rd).toBeFalse();
      });

      test('RA flag should be off', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_ra).toBeFalse();
      });

      test('Z flag should be off', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_z).toBeFalse();
      });

      test('RCODE should be honoured', () => {
        const rcode = 15;
        const message = new Message({ ...STUB_HEADER, rcode }, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).rcode).toEqual('RCODE_15');
      });
    });

    describe('Question', () => {
      test('There should be no question records', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).questions).toHaveLength(0);
      });
    });

    describe('Answer', () => {
      test('No records should be output if there are none', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers).toHaveLength(0);
      });

      test('One record should be output if there is one', () => {
        const message = new Message(STUB_HEADER, [RECORD]);

        const serialisation = message.serialise();

        const answers = decode(serialisation).answers;
        expect(answers).toHaveLength(1);
        expect(answers![0].name).toEqual(RECORD_NAME.replace(/\.$/, ''));
        expect(answers![0].type).toEqual(RECORD_TYPE);
        expect(answers![0].class).toEqual('IN');
        expect(answers![0].ttl).toEqual(RECORD_TTL);
        expect(answers![0].data).toHaveLength(1);
        expect((answers![0].data as TxtData)[0]).toEqual(RECORD_DATA_TXT_DATA);
      });

      test('Multiple records should be output if there are multiple', () => {
        const answer2Rdata = Buffer.alloc(2);
        answer2Rdata.writeUInt8(1);
        answer2Rdata.writeUInt8(42, 1);
        const answer2 = new Record(
          RECORD_NAME,
          RECORD_TYPE_ID,
          DNSClass.IN,
          RECORD_TTL,
          answer2Rdata,
        );
        const message = new Message(STUB_HEADER, [RECORD, answer2]);

        const serialisation = message.serialise();

        const answers = decode(serialisation).answers;
        expect(answers).toHaveLength(2);
        expect((answers![0].data as TxtData)[0]).toEqual(RECORD_DATA_TXT_DATA);
        expect((answers![1].data as TxtData)[0]).toEqual(answer2Rdata.subarray(1));
      });
    });

    describe('Authority', () => {
      test('There should be no authority records', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).authorities).toHaveLength(0);
      });
    });

    describe('Additional', () => {
      test('There should be no additional records', () => {
        const message = new Message(STUB_HEADER, []);

        const serialisation = message.serialise();

        expect(decode(serialisation).additionals).toHaveLength(0);
      });
    });
  });

  describe('deserialise', () => {
    const record: DPAnswer = {
      type: RECORD_TYPE,
      class: RECORD_CLASS_STR,
      name: RECORD_NAME,
      ttl: RECORD_TTL,
      data: RECORD_DATA.toString(),
    };

    describe('Header', () => {
      test('RCODE should be extracted', () => {
        const messageSerialised = encode({
          type: 'response',
          rcode: 'RCODE_15',
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.header.rcode).toEqual(15);
      });
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
          answers: [record],
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.answers).toHaveLength(1);
        expect(message.answers[0]).toMatchObject<Partial<Record>>({
          name: RECORD_NAME,
          type: RECORD_TYPE_ID,
          class_: RECORD_CLASS,
          ttl: RECORD_TTL,
        });
        expect(Buffer.from(message.answers[0].dataSerialised)).toEqual(RECORD_DATA);
      });

      test('Multiple answers should be output if the message had multiple', () => {
        const record2: TxtAnswer = {
          data: 'foo',
          name: 'foo.example.com.',
          type: 'TXT',
          ttl: RECORD_TTL,
        };
        const messageSerialised = encode({
          type: 'response',
          answers: [record, record2],
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.answers).toHaveLength(2);
        expect(message.answers[0]).toMatchObject<Partial<Record>>({
          name: RECORD_NAME,
          type: RECORD_TYPE_ID,
          class_: DNSClass.IN,
          ttl: RECORD_TTL,
        });
        expect(Buffer.from(message.answers[0].dataSerialised)).toEqual(RECORD_DATA);
        expect(message.answers[1]).toMatchObject<Partial<Record>>({
          name: record2.name,
          type: 16,
          class_: DNSClass.IN,
          ttl: record2.ttl,
        });
        expect(Buffer.from(message.answers[1].dataSerialised)).toEqual(
          Buffer.from(record2.data as string),
        );
      });

      test('Questions should be ignored', () => {
        const question: Question = { type: RECORD_TYPE, class: 'IN', name: `not-${RECORD_NAME}` };
        const messageSerialised = encode({
          type: 'response',
          answers: [record],
          questions: [question, question],
        });

        const message = Message.deserialise(messageSerialised);

        expect(message.answers).toHaveLength(1);
        expect(message.answers[0].name).toEqual(RECORD_NAME);
      });

      test('Answers should be capped at the length prefix', () => {
        const serialisation = serialiseMessage([record, record], 1);

        const message = Message.deserialise(serialisation);

        expect(message.answers).toHaveLength(1);
      });

      test('Empty serialisation should be regarded malformed', () => {
        const serialisation = Buffer.from([]);

        expect(() => Message.deserialise(serialisation)).toThrowWithMessage(
          MalformedMessage,
          'Message serialisation does not comply with RFC 1035 (Section 4)',
        );
      });

      test('Serialisation should be regarded malformed if ANCOUNT is too high', () => {
        const serialisation = serialiseMessage([record], 2);

        expect(() => Message.deserialise(serialisation)).toThrowWithMessage(
          MalformedMessage,
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
  });
});
