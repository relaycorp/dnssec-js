import type { Question } from './utils/dns/Question.js';
import type { Message } from './utils/dns/Message.js';

export type Resolver = (question: Question) => Promise<Buffer | Message>;
