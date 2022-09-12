import { DNSClass } from './DNSClass';

export interface Answer {
  readonly name: string;
  readonly type: number;
  readonly class: DNSClass;
  readonly ttl: number;
  readonly data: Buffer;
}
