import { Answer } from './Answer';
import { DNS_MESSAGE_PARSER } from './parser';
import { MalformedMessage } from './MalformedMessage';

// tslint:disable-next-line:no-bitwise
const RESPONSE_FLAG = 1 << 15;

/**
 * Partial representation of DNS messages (the generalisation for "queries" and "answers").
 *
 * We're only interested in the answers, so we'll ignore everything else, such as the header or
 * the question.
 *
 * This implements a tiny subset of the format described in RFC 1035 (Section 4).
 */
export class Message {
  public static deserialise(serialisation: Uint8Array): Message {
    let messageParts: any;
    try {
      messageParts = DNS_MESSAGE_PARSER.parse(serialisation);
    } catch (_) {
      throw new MalformedMessage('Message serialisation does not comply with RFC 1035 (Section 4)');
    }
    return new Message(messageParts.answers);
  }

  constructor(public readonly answers: readonly Answer[]) {}

  public serialise(): Uint8Array {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(RESPONSE_FLAG, 2);
    header.writeUInt16BE(this.answers.length, 6);

    const answers = this.answers.map(serialiseRecord);

    return Buffer.concat([header, ...answers]);
  }
}

function serialiseRecord(answer: Answer): Buffer {
  const labelsSerialised = serialiseName(answer.name);

  const typeSerialised = Buffer.allocUnsafe(2);
  typeSerialised.writeUInt16BE(answer.type);

  const classSerialised = Buffer.allocUnsafe(2);
  classSerialised.writeUInt16BE(answer.class);

  const ttlSerialised = Buffer.allocUnsafe(4);
  ttlSerialised.writeUInt32BE(answer.ttl);

  const dataLengthSerialised = Buffer.allocUnsafe(2);
  dataLengthSerialised.writeUInt16BE(answer.data.length);

  return Buffer.concat([
    labelsSerialised,
    typeSerialised,
    classSerialised,
    ttlSerialised,
    dataLengthSerialised,
    answer.data,
  ]);
}

function serialiseName(name: string): Buffer {
  const labels = name
    .replace(/\.$/, '')
    .split('.')
    .map((label) => {
      const labelSerialised = Buffer.from(label);
      const lengthPrefix = Buffer.from([labelSerialised.byteLength]);
      return Buffer.concat([lengthPrefix, labelSerialised]);
    });
  return Buffer.concat([...labels, Buffer.from([0])]);
}
