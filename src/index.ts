/* eslint-disable import/no-unused-modules */

// DNS-related
export type { IanaRrTypeName, IanaRrTypeIdOrName } from './lib/dns/ianaRrTypes.js';
export type { DnsClassIdOrName } from './lib/dns/ianaClasses.js';
export type { DnsClassName } from './lib/dns/ianaClasses.js';
export { DnsClass } from './lib/dns/ianaClasses.js';
export type { Header } from './lib/dns/Header.js';
export { Message } from './lib/dns/Message.js';
export { Question } from './lib/dns/Question.js';
export { DnsRecord } from './lib/dns/DnsRecord.js';
export { RrSet } from './lib/dns/RrSet.js';

// DNSSEC-related
export { DatePeriod } from './lib/DatePeriod.js';
export { DigestType } from './lib/DigestType.js';
export { DnssecAlgorithm } from './lib/DnssecAlgorithm.js';
export type { Resolver } from './lib/Resolver.js';
export { dnssecLookUp } from './lib/lookup.js';
export type { ChainVerificationResult, FailureResult, VerifiedRrSet } from './lib/results.js';
export { SecurityStatus } from './lib/SecurityStatus.js';
export type { TrustAnchor } from './lib/TrustAnchor.js';
export type { VerificationOptions } from './lib/VerificationOptions.js';
