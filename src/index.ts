/* eslint-disable import/no-unused-modules */

// DNS-related
export type { IanaRrTypeName, IanaRrTypeIdOrName } from './lib/dns/ianaRrTypes';
export type { DnsClassIdOrName } from './lib/dns/ianaClasses';
export { DnsClass } from './lib/dns/ianaClasses';
export type { Header } from './lib/dns/Header';
export { Message } from './lib/dns/Message';
export { Question } from './lib/dns/Question';
export { DnsRecord } from './lib/dns/DnsRecord';
export { RRSet } from './lib/dns/RRSet';

// DNSSEC-related
export { DatePeriod } from './lib/DatePeriod';
export type { Resolver } from './lib/Resolver';
export { dnssecLookUp } from './lib/lookup';
export type { ChainVerificationResult, FailureResult, VerifiedRRSet } from './lib/results';
export { SecurityStatus } from './lib/SecurityStatus';
export type { TrustAnchor } from './lib/TrustAnchor';
