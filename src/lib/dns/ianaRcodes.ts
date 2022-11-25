/* eslint-disable import/exports-last */
/**
 * DNS RCODEs
 *
 * See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
 */
import { DnsError } from './DnsError';

export const RCODE_IDS = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
  YXDOMAIN: 6,
  YXRRSET: 7,
  NXRRSET: 8,
  NOTAUTH: 9,
  NOTZONE: 10,
  DSOTYPENI: 11,
  BADVERS: 16,
  BADKEY: 17,
  BADTIME: 18,
  BADMODE: 19,
  BADNAME: 20,
  BADALG: 21,
  BADTRUNC: 22,
  BADCOOKIE: 23,
};

type RcodeName = keyof typeof RCODE_IDS;
export type RcodeIdOrName = RcodeName | number;

const RCODE_IDS_NORMALISED: { readonly [name: string]: number } = Object.entries(RCODE_IDS).reduce(
  (accumulator, [name, id]) => ({ ...accumulator, [name.toUpperCase()]: id }),
  {},
);

export function getRcodeId(codeName: RcodeIdOrName): number {
  if (typeof codeName === 'number') {
    return codeName;
  }

  const codeNameSanitised = codeName.toUpperCase();
  if (!(codeNameSanitised in RCODE_IDS_NORMALISED)) {
    throw new DnsError(`DNS RCode "${codeName}" is not defined by IANA`);
  }

  return RCODE_IDS_NORMALISED[codeNameSanitised];
}
