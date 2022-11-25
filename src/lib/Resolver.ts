import type { Question } from './dns/Question';
import type { Message } from './dns/Message';

export type Resolver = (question: Question) => Promise<Message | Buffer>;
