import { Record } from './Record';
import { DNS_MESSAGE_PARSER } from './parser';
import { MalformedMessage } from './MalformedMessage';
import { Header } from './Header';
import { Question } from './Question';

// tslint:disable-next-line:no-bitwise
const RESPONSE_FLAG = 1 << 15;
const RCODE_MASK = 0b00001111;

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

    const rcode = messageParts.queryParams[1] ^ RCODE_MASK;
    return new Message({ rcode }, messageParts.questions, messageParts.answers);
  }

  constructor(
    public readonly header: Header,
    public readonly questions: readonly Question[],
    public readonly answers: readonly Record[],
  ) {}

  public serialise(): Uint8Array {
    const header = Buffer.alloc(12);

    const queryParams = RESPONSE_FLAG + this.header.rcode;
    header.writeUInt16BE(queryParams, 2);

    header.writeUInt16BE(this.questions.length, 4);
    header.writeUInt16BE(this.answers.length, 6);

    const questions = this.questions.map((q) => q.serialise());
    const answers = this.answers.map((a) => a.serialise());

    return Buffer.concat([header, ...questions, ...answers]);
  }

  /**
   * Report whether this message answers the `question`.
   *
   * That is, whether the message questions contains `question`.
   *
   * @param question
   */
  public answersQuestion(question: Question): boolean {
    return this.questions.some((q) => question.equals(q));
  }
}
