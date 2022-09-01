import { Record } from './Record.js';

/**
 * Partial representation of DNS messages (the generalisation for "queries" and "answers").
 *
 * We're only interested in the answers, so we'll ignore everything else, such as the header or
 * question.
 */
export class Message {
  public static deserialise(serialisation: Buffer): Message {
    throw new Error(serialisation.toString());
  }

  constructor(public readonly answer: readonly Record[]) {}
}
