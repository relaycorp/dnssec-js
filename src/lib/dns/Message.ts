import { decode, Packet } from '@leichtgewicht/dns-packet';

import { Record } from './Record';
import { Header } from './Header';
import { Question } from './Question';
import { DnsError } from './DnsError';
import { IanaRrTypeName } from './ianaRrTypes';
import { DnsClassName } from './ianaClasses';
import { getRcodeId } from './ianaRcodes';

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
    let messageParts: Packet;
    try {
      messageParts = decode(serialisation);
    } catch (_) {
      throw new DnsError('Message serialisation does not comply with RFC 1035 (Section 4)');
    }

    const rcode = getRcodeId(messageParts.rcode as any);
    const questions = messageParts.questions!.map(
      (q) => new Question(q.name, q.type as IanaRrTypeName, q.class!),
    );
    const answers = messageParts.answers!.map(
      (a) => new Record(a.name, a.type, a.class as DnsClassName, a.ttl!, a.data as any),
    );
    return new Message({ rcode }, questions, answers);
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
