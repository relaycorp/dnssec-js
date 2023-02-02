/* eslint-disable import/no-unused-modules */

// DNS-related
export type { IanaRrTypeName, IanaRrTypeIdOrName } from './lib/utils/dns/ianaRrTypes.js';
export type { DnsClassIdOrName } from './lib/utils/dns/ianaClasses.js';
export type { DnsClassName } from './lib/utils/dns/ianaClasses.js';
export { DnsClass } from './lib/utils/dns/ianaClasses.js';
export type { Header } from './lib/utils/dns/Header.js';
export { Message } from './lib/utils/dns/Message.js';
export { Question } from './lib/utils/dns/Question.js';
export { DnsRecord } from './lib/utils/dns/DnsRecord.js';
export { RrSet } from './lib/utils/dns/RrSet.js';

// DNSSEC-related
export { DatePeriod } from './lib/DatePeriod.js';
export { DigestType } from './lib/DigestType.js';
export { DnssecAlgorithm } from './lib/DnssecAlgorithm.js';
export type { Resolver } from './lib/Resolver.js';
export { dnssecLookUp } from './lib/lookup.js';
export { SecurityStatus } from './lib/SecurityStatus.js';
export type {
  ChainVerificationResult,
  FailureResult,
  FailureStatus,
  VerifiedRrSet,
} from './lib/securityStatusResults.js';
export type { TrustAnchor } from './lib/TrustAnchor.js';
export type { VerificationOptions } from './lib/VerificationOptions.js';

// Test utilities
export { MockChain } from './lib/testing/MockChain.js';
export type { MockChainFixture } from './lib/testing/MockChainFixture.js';
