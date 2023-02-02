import type { Question } from './utils/dns/Question.js';
import type { Resolver } from './Resolver.js';
import type { VerificationOptions } from './VerificationOptions.js';
import type { ChainVerificationResult } from './securityStatusResults.js';
import { UnverifiedChain } from './UnverifiedChain.js';
import { DatePeriod, type IDatePeriod } from './dates.js';
import type { TrustAnchor } from './TrustAnchor.js';
import { DsData } from './records/DsData.js';
import { IANA_TRUST_ANCHORS } from './ianaTrustAnchors.js';

function convertTrustAnchors(trustAnchors: readonly TrustAnchor[]): readonly DsData[] {
  return trustAnchors.map(
    (anchor) => new DsData(anchor.keyTag, anchor.algorithm, anchor.digestType, anchor.digest),
  );
}

function convertDatePeriod(dateOrPeriod: Date | IDatePeriod) {
  return dateOrPeriod instanceof Date
    ? DatePeriod.init(dateOrPeriod, dateOrPeriod)
    : DatePeriod.init(dateOrPeriod.start, dateOrPeriod.end);
}

/**
 * Retrieve RRset for `question` and return it only if DNSSEC validation succeeds.
 */
export async function dnssecLookUp(
  question: Question,
  resolver: Resolver,
  options: Partial<VerificationOptions> = {},
): Promise<ChainVerificationResult> {
  const unverifiedChain = await UnverifiedChain.retrieve(question, resolver);
  const datePeriod = convertDatePeriod(options.dateOrPeriod ?? new Date());
  const dsData = options.trustAnchors
    ? convertTrustAnchors(options.trustAnchors)
    : IANA_TRUST_ANCHORS;
  return unverifiedChain.verify(datePeriod, dsData);
}
