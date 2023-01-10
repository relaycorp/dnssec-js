/* eslint-disable import/exports-last */
/**
 * DNS CLASSes.
 *
 * See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
 */

import { DnsError } from './DnsError.js';

export enum DnsClass {
  IN = 1,
  CH = 3,
  HS = 4,
}

const DNS_CLASS_IDS: { readonly [name: string]: DnsClass } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  IN: DnsClass.IN,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  CH: DnsClass.CH,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  HS: DnsClass.HS,
};

/**
 * DNS class name.
 */
export type DnsClassName = keyof typeof DNS_CLASS_IDS;

const DNS_CLASS_NAMES: { readonly [name: number]: DnsClassName } = Object.fromEntries(
  Object.entries(DNS_CLASS_IDS).map(([name, id]) => [id, name as DnsClassName]),
);

export type DnsClassIdOrName = DnsClass | DnsClassName;

export function getDnsClassId(className: DnsClassIdOrName): DnsClass {
  if (typeof className === 'number') {
    return className;
  }

  if (!(className in DNS_CLASS_IDS)) {
    throw new DnsError(`DNS class name "${className}" is not defined by IANA`);
  }

  return DNS_CLASS_IDS[className];
}

export function getDnsClassName(classId: DnsClass): DnsClassName {
  const name = DNS_CLASS_NAMES[classId];
  if (name === undefined) {
    throw new DnsError(`DNS class id "${classId}" is not defined by IANA`);
  }
  return name;
}
