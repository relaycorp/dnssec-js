import type { DnskeyRecord, DsRecord, RrsigRecord } from '../../dnssecRecords.js';
import type { Message } from '../../dns/Message.js';

interface DnssecResponseMixin {
  readonly message: Message;
}

interface SignedResponseMixin {
  readonly rrsig: RrsigRecord;
}

export interface DnskeyResponse extends DnssecResponseMixin, SignedResponseMixin, DnskeyRecord {}

export interface DsResponse extends DnssecResponseMixin, SignedResponseMixin, DsRecord {}

export interface RrsigResponse extends DnssecResponseMixin, RrsigRecord {}

export interface ZoneResponseSet {
  readonly dnskey: DnskeyResponse;
  readonly ds: DsResponse;
}
