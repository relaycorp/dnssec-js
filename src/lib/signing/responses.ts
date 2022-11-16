import { DnskeyRecord, DsRecord, RrsigRecord } from '../dnssecRecords';
import { Message } from '../dns/Message';

interface DnssecResponseMixin {
  readonly message: Message;
}

export interface DnskeyResponse extends DnssecResponseMixin, DnskeyRecord {}

export interface DsResponse extends DnssecResponseMixin, DsRecord {}

export interface RrsigResponse extends DnssecResponseMixin, RrsigRecord {}

export interface ZoneResponseSet {
  readonly dnskey: DnskeyResponse;
  readonly ds: DsResponse;
}
