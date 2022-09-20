import { Record } from './Record';
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

  constructor(public readonly answers: readonly Record[]) {}

  public serialise(): Uint8Array {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(RESPONSE_FLAG, 2);
    header.writeUInt16BE(this.answers.length, 6);

    const answers = this.answers.map((a) => a.serialise());

    return Buffer.concat([header, ...answers]);
  }
}
