import type { Question } from './dns/Question.js';
import type { Message } from './dns/Message.js';

export type Resolver = (question: Question) => Promise<Message | Uint8Array>;
