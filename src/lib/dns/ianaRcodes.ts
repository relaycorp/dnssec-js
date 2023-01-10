/* eslint-disable import/exports-last,@typescript-eslint/naming-convention */
/**
 * DNS RCODEs
 *
 * See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
 */
import { DnsError } from './DnsError.js';

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

export type RcodeName = keyof typeof RCODE_IDS;
export type RcodeIdOrName = RcodeName | number;

const RCODE_IDS_NORMALISED: { readonly [name: string]: number } = Object.entries(RCODE_IDS).reduce(
  (accumulator, [name, id]) => ({ ...accumulator, [name.toUpperCase()]: id }),
  {},
);

const RCODE_NAMES: { readonly [name: number]: RcodeName } = Object.fromEntries(
  Object.entries(RCODE_IDS_NORMALISED).map(([name, id]) => [id, name as RcodeName]),
);

export function getRcodeId(codeName: RcodeIdOrName): number {
  if (typeof codeName === 'number') {
    return codeName;
  }

  const codeNameSanitised = codeName.toUpperCase();
  const id = RCODE_IDS_NORMALISED[codeNameSanitised] as number | undefined;
  if (id === undefined) {
    throw new DnsError(`DNS RCode name "${codeName}" is not defined by IANA`);
  }

  return id;
}

export function getRcodeName(codeId: number): RcodeName {
  const name = RCODE_NAMES[codeId] as RcodeName | undefined;
  if (!name) {
    throw new DnsError(`DNS RCode id ${codeId} is not defined by IANA`);
  }
  return name;
}
