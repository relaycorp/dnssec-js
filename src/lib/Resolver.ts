import { Question } from './dns/Question';
import { Message } from './dns/Message';

export type Resolver = (question: Question) => Promise<Message | Buffer>;
