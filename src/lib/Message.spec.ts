import { decode, encode, TxtAnswer } from '@leichtgewicht/dns-packet';

import { Message } from './Message.js';
import { MalformedDNSMessage } from './MalformedDNSMessage.js';
import { Record } from './Record.js';
import { DNSClass } from './DNSClass.js';
import {
  RECORD_CLASS,
  RECORD_CLASS_STR,
  RECORD_DATA,
  RECORD_DATA_TXT_DATA,
  RECORD_NAME,
  RECORD_TTL,
  RECORD_TYPE,
  RECORD_TYPE_ID,
} from '../testUtils/stubs.js';

describe('Message', () => {
  describe('serialise', () => {
    describe('Header', () => {
      test('Id should be set to 0', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).id).toEqual(0);
      });

      test('QR flag should be on (response message)', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_qr).toBeTrue();
      });

      test('OPCODE should be set to 0 (QUERY)', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).opcode).toEqual('QUERY');
      });

      test('AA flag should be off', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_aa).toBeFalse();
      });

      test('TC flag should be off', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_tc).toBeFalse();
      });

      test('RD flag should be off', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_rd).toBeFalse();
      });

      test('RA flag should be off', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_ra).toBeFalse();
      });

      test('Z flag should be off', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).flag_z).toBeFalse();
      });

      test('RCODE should be 0 (NOERROR)', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).rcode).toEqual('NOERROR');
      });
    });

    describe('Question', () => {
      test('There should be no question records', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).questions).toHaveLength(0);
      });
    });

    describe('Answer', () => {
      const record: Record = {
        data: RECORD_DATA,
        class: RECORD_CLASS,
        name: RECORD_NAME,
        ttl: RECORD_TTL,
        type: RECORD_TYPE_ID,
      };

      test('No records should be output if there are none', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers).toHaveLength(0);
      });

      test('One record should be output if there is one', () => {
        const message = new Message([record]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers).toHaveLength(1);
      });

      test('Multiple records should be output if there are multiple', () => {
        const message = new Message([record, record]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers).toHaveLength(2);
      });

      test('Record name should be serialised', () => {
        const message = new Message([record]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers![0]).toHaveProperty('name', record.name);
      });

      test('Trailing dot in record name should be ignored', () => {
        const nameWithoutDot = record.name.replace(/\.$/, '');
        const name = nameWithoutDot + '.';
        const record2: Record = { ...record, name };
        const message = new Message([record2]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers![0]).toHaveProperty('name', nameWithoutDot);
      });

      test('Missing trailing dot in record name should be supported', () => {
        const nameWithoutDot = record.name.replace(/\.$/, '');
        const record2: Record = { ...record, name: nameWithoutDot };
        const message = new Message([record2]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers![0]).toHaveProperty('name', nameWithoutDot);
      });

      test('Record type should be serialised', () => {
        const message = new Message([record]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers![0]).toHaveProperty('type', RECORD_TYPE);
      });

      test('Record class should be serialised', () => {
        const message = new Message([record]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers![0]).toHaveProperty('class', RECORD_CLASS_STR);
      });

      test('Record TTL should be serialised', () => {
        const message = new Message([record]);

        const serialisation = message.serialise();

        expect(decode(serialisation).answers![0]).toHaveProperty('ttl', record.ttl);
      });

      test('Record data should be serialised', () => {
        const message = new Message([record]);

        const serialisation = message.serialise();

        const answer = decode(serialisation).answers![0];
        expect(answer.data).toHaveLength(1);
        expect(RECORD_DATA_TXT_DATA.equals((answer.data as any)[0])).toBeTrue();
      });
    });

    describe('Authority', () => {
      test('There should be no authority records', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).authorities).toHaveLength(0);
      });
    });

    describe('Additional', () => {
      test('There should be no additional records', () => {
        const message = new Message([]);

        const serialisation = message.serialise();

        expect(decode(serialisation).additionals).toHaveLength(0);
      });
    });
  });

  describe('deserialise', () => {
    test('Malformed messages should be refused', () => {
      const malformedMessages = [Buffer.from([])];

      malformedMessages.forEach((message) => {
        expect(() => Message.deserialise(message)).toThrowWithMessage(
          MalformedDNSMessage,
          'Message serialisation does not comply with RFC 1035 (Section 4)',
        );
      });
    });

    test('No answer should be output of the message had none', () => {
      const messageSerialised = encode({
        type: 'response',
        answers: [],
      });

      const message = Message.deserialise(messageSerialised);

      expect(message.answer).toBeEmpty();
    });

    test('One answer should be output if the message had one', () => {
      const messageSerialised = encode({
        type: 'response',
        answers: [
          {
            type: RECORD_TYPE,
            class: RECORD_CLASS_STR,
            name: RECORD_NAME,
            ttl: RECORD_TTL,
            data: RECORD_DATA.toString(),
          },
        ],
      });

      const message = Message.deserialise(messageSerialised);

      expect(message.answer).toHaveLength(1);
      expect(message.answer[0]).toEqual<Partial<Record>>({
        name: RECORD_NAME,
        type: RECORD_TYPE_ID,
        class: RECORD_CLASS,
        ttl: RECORD_TTL,
        data: RECORD_DATA,
      });
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
        answers: [
          {
            type: RECORD_TYPE,
            class: RECORD_CLASS_STR,
            name: RECORD_NAME,
            ttl: RECORD_TTL,
            data: RECORD_DATA.toString(),
          },
          record2,
        ],
      });

      const message = Message.deserialise(messageSerialised);

      expect(message.answer).toHaveLength(2);
      expect(message.answer[0]).toEqual<Partial<Record>>({
        name: RECORD_NAME,
        type: RECORD_TYPE_ID,
        class: DNSClass.IN,
        ttl: RECORD_TTL,
        data: RECORD_DATA,
      });
      expect(message.answer[1]).toEqual<Partial<Record>>({
        name: record2.name,
        type: 16,
        class: DNSClass.IN,
        ttl: record2.ttl,
        data: Buffer.from(record2.data as string),
      });
    });

    test.todo('Answers should be capped at the length prefix');

    test.todo('Length prefix should be ignored if actual number of answers is lower');
  });
});
