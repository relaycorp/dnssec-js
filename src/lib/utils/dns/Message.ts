import type { Packet } from '@leichtgewicht/dns-packet';
import {
  decode,
  encode,
  type Answer,
  type Question as DpQuestion,
  type RecordClass,
} from '@leichtgewicht/dns-packet';

import { DnsRecord } from './DnsRecord.js';
import type { Header } from './Header.js';
import { Question } from './Question.js';
import { DnsError } from './DnsError.js';
import type { IanaRrTypeName } from './ianaRrTypes.js';
import type { DnsClassName } from './ianaClasses.js';
import type { RcodeName } from './ianaRcodes.js';
import { getRcodeId, getRcodeName } from './ianaRcodes.js';
import { getRrTypeName } from './ianaRrTypes.js';
import { getDnsClassName } from './ianaClasses.js';

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
    } catch {
      throw new DnsError('Message serialisation does not comply with RFC 1035 (Section 4)');
    }

    const rcode = getRcodeId(messageParts.rcode as RcodeName);
    const questions = messageParts.questions!.map(
      (question) => new Question(question.name, question.type as IanaRrTypeName, question.class),
    );
    const answers = messageParts.answers!.map(
      (answer) =>
        new DnsRecord(
          answer.name,
          answer.type,
          answer.class as DnsClassName,
          answer.ttl!,
          answer.data as object,
        ),
    );
    return new Message({ rcode }, questions, answers);
  }

  public constructor(
    public readonly header: Header,
    public readonly questions: readonly Question[],
    public readonly answers: readonly DnsRecord[],
  ) {}

  public serialise(): Uint8Array {
    const rcode = getRcodeName(this.header.rcode);
    const questions: DpQuestion[] = this.questions.map((question) => ({
      name: question.name,
      type: question.getTypeName(),
    }));
    const answers: Answer[] = this.answers.map((answer) => ({
      name: answer.name,
      type: getRrTypeName(answer.typeId) as any,
      ttl: answer.ttl,
      class: getDnsClassName(answer.classId) as RecordClass,
      data: answer.dataFields,
    }));
    return encode({ rcode, questions, answers });
  }

  /**
   * Report whether this message answers the `question`.
   *
   * That is, whether the message questions contains `question`.
   */
  public answersQuestion(question: Question): boolean {
    return this.questions.some((messageQuestion) => question.equals(messageQuestion));
  }
}
