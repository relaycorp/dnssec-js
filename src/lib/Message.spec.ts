// @ts-ignore
const { encode: encodePacket } = import('dns-packet');

import { Message } from './Message.js';
import { MalformedDNSMessage } from './MalformedDNSMessage.js';
import { Record } from './Record.js';
import { DNSClass } from './DNSClass.js';
import {
  RECORD_DATA,
  RECORD_NAME,
  RECORD_TTL,
  RECORD_TYPE,
  RECORD_TYPE_ID,
} from '../testUtils/stubs.js';

describe('Message', () => {
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
      const messageSerialised = encodePacket({
        type: 'response',
        answers: [],
      });

      const message = Message.deserialise(messageSerialised);

      expect(message.answer).toBeEmpty();
    });

    test('One answer should be output if the message had one', () => {
      const messageSerialised = encodePacket({
        type: 'response',
        answers: [
          {
            type: RECORD_TYPE,
            class: 'IN',
            name: RECORD_NAME,
            ttl: RECORD_TTL,
            data: RECORD_DATA,
          },
        ],
      });

      const message = Message.deserialise(messageSerialised);

      expect(message.answer).toHaveLength(1);
      expect(message.answer[0]).toEqual<Partial<Record>>({
        name: RECORD_NAME,
        type: RECORD_TYPE_ID,
        klass: DNSClass.IN,
        ttl: RECORD_TTL,
        data: RECORD_DATA,
      });
    });

    test('Multiple answers should be output if the message had multiple', () => {
      const record2 = { data: 'foo', name: 'foo.example.com.', type: 'TXT', ttl: RECORD_TTL };
      const messageSerialised = encodePacket({
        type: 'response',
        answers: [
          {
            type: RECORD_TYPE,
            class: 'IN',
            name: RECORD_NAME,
            ttl: RECORD_TTL,
            data: RECORD_DATA,
          },
          // @ts-ignore
          record2,
        ],
      });

      const message = Message.deserialise(messageSerialised);

      expect(message.answer).toHaveLength(2);
      expect(message.answer[0]).toEqual<Partial<Record>>({
        name: RECORD_NAME,
        type: RECORD_TYPE_ID,
        klass: DNSClass.IN,
        ttl: RECORD_TTL,
        data: RECORD_DATA,
      });
      expect(message.answer[1]).toEqual<Partial<Record>>({
        name: record2.name,
        type: 16,
        klass: DNSClass.IN,
        ttl: record2.ttl,
        // @ts-ignore
        data: record2.data,
      });
    });

    test.todo('Answers should be capped at the length prefix');

    test.todo('Length prefix should be ignored if actual number of answers is lower');
  });
});
