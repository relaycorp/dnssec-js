import { DNSClass } from './DNSClass';

export interface Question {
  readonly name: string;
  readonly type: number;
  readonly class: DNSClass;
}
