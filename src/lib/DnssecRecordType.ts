/* eslint-disable @typescript-eslint/prefer-literal-enum-member */

import { IANA_RR_TYPE_IDS } from './dns/ianaRrTypes';

export enum DnssecRecordType {
  DS = IANA_RR_TYPE_IDS.DS,
  RRSIG = IANA_RR_TYPE_IDS.RRSIG,
  DNSKEY = IANA_RR_TYPE_IDS.DNSKEY,
}
