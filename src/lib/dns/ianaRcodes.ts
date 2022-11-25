/**
 * DNS RCODEs
 *
 * @link https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
 */
import { DnsError } from './DnsError';

export const RCODE_IDS = {
  NoError: 0,
  FormErr: 1,
  ServFail: 2,
  NXDomain: 3,
  NotImp: 4,
  Refused: 5,
  YXDomain: 6,
  YXRRSet: 7,
  NXRRSet: 8,
  NotAuth: 9,
  NotZone: 10,
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

export type RcodeName = keyof typeof RCODE_IDS;
export type RcodeIdOrName = RcodeName | number;

const RCODE_IDS_NORMALISED: { readonly [name: string]: number } = Object.entries(RCODE_IDS).reduce(
  (accumulator, [name, id]) => ({ ...accumulator, [name.toUpperCase()]: id }),
  {},
);

export function getRcodeId(codeName: RcodeIdOrName): number {
  if (typeof codeName === 'number') {
    return codeName;
  }

  const codeId = RCODE_IDS_NORMALISED[codeName.toUpperCase()];
  if (codeId === undefined) {
    throw new DnsError(`DNS RCode "${codeName}" is not defined by IANA`);
  }

  return codeId;
}
