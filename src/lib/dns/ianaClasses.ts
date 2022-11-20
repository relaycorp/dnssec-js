/**
 * DNS CLASSes.
 *
 * @link https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
 */

import { DnsError } from './DnsError';

export enum DnsClass {
  IN = 1,
  CH = 3,
  HS = 4,
}

const DNS_CLASS_IDS: { readonly [name: string]: DnsClass } = {
  IN: DnsClass.IN,
  CH: DnsClass.CH,
  HS: DnsClass.HS,
};

export type DnsClassName = keyof typeof DNS_CLASS_IDS;

export type DnsClassIdOrName = DnsClass | DnsClassName;

export function getDnsClassId(className: DnsClassIdOrName): DnsClass {
  if (typeof className === 'number') {
    return className;
  }

  const classId = DNS_CLASS_IDS[className];
  if (classId === undefined) {
    throw new DnsError(`DNS class "${className}" is not defined by IANA`);
  }

  return classId;
}
