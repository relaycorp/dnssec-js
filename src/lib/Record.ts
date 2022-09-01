import { DNSClass } from './DNSClass.js';

export class Record {
  constructor(
    public readonly name: string,
    public readonly type: number,
    public readonly klass: DNSClass,
    public readonly ttl: number,
    public readonly data: string,
  ) {}

  public serialise(): Buffer {
    throw new Error('sfsw');
  }
}
