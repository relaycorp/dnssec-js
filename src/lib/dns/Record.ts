import { DNSClass } from './DNSClass';

export interface Record {
  readonly name: string;
  readonly type: number;
  readonly class: DNSClass;
  readonly ttl: number;
  readonly data: Buffer;
}
