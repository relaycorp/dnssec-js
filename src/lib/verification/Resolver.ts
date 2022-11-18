import { Question } from '../dns/Question';
import { Message } from '../dns/Message';

export type Resolver = (q: Question) => Promise<Message>;
