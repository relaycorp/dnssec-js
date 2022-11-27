/**
 * IANA Resource Record (RR) Types.
 *
 * Excluding special types, such as reserved ones, `*` and ranges.
 *
 * See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
 */

import { DnsError } from './DnsError.js';

export const IANA_RR_TYPE_IDS = {
  // eslint-disable-next-line id-length
  A: 1,
  NS: 2,
  MD: 3,
  MF: 4,
  CNAME: 5,
  SOA: 6,
  MB: 7,
  MG: 8,
  MR: 9,
  NULL: 10,
  WKS: 11,
  PTR: 12,
  HINFO: 13,
  MINFO: 14,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  X25: 19,
  ISDN: 20,
  RT: 21,
  NSAP: 22,
  NSAP_PTR: 23,
  SIG: 24,
  KEY: 25,
  PX: 26,
  GPOS: 27,
  AAAA: 28,
  LOC: 29,
  NXT: 30,
  EID: 31,
  NIMLOC: 32,
  SRV: 33,
  ATMA: 34,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  A6: 38,
  DNAME: 39,
  SINK: 40,
  OPT: 41,
  APL: 42,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  UNASSIGNED: 54,
  HIP: 55,
  NINFO: 56,
  RKEY: 57,
  TALINK: 58,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  UINFO: 100,
  UID: 101,
  GID: 102,
  UNSPEC: 103,
  NID: 104,
  L32: 105,
  L64: 106,
  LP: 107,
  EUI48: 108,
  EUI64: 109,
  TKEY: 249,
  TSIG: 250,
  IXFR: 251,
  AXFR: 252,
  MAILB: 253,
  MAILA: 254,
  URI: 256,
  CAA: 257,
  AVC: 258,
  DOA: 259,
  AMTRELAY: 260,
  TA: 32_768,
  DLV: 32_769,
};

export type IanaRrTypeName = keyof typeof IANA_RR_TYPE_IDS;
export type IanaRrTypeIdOrName = IanaRrTypeName | number;

export const IANA_RR_TYPE_NAMES: { [key: number]: IanaRrTypeName } = Object.entries(
  IANA_RR_TYPE_IDS,
).reduce((accumulator, [name, id]) => ({ ...accumulator, [id]: name as IanaRrTypeName }), {});

export function getRrTypeId(typeName: IanaRrTypeIdOrName): number {
  if (typeof typeName === 'number') {
    return typeName;
  }

  if (!(typeName in IANA_RR_TYPE_IDS)) {
    throw new DnsError(`RR type name "${typeName}" is not defined by IANA`);
  }

  return IANA_RR_TYPE_IDS[typeName];
}

export function getRrTypeName(typeId: number | string): IanaRrTypeName {
  if (typeof typeId === 'string') {
    return typeId as IanaRrTypeName;
  }

  if (!(typeId in IANA_RR_TYPE_NAMES)) {
    throw new DnsError(`RR type id "${typeId}" is not defined by IANA`);
  }

  return IANA_RR_TYPE_NAMES[typeId];
}
