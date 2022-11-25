import type { Question } from './dns/Question.js';
import type { Resolver } from './Resolver.js';
import type { VerificationOptions } from './VerificationOptions.js';
import type { ChainVerificationResult } from './results.js';
import { UnverifiedChain } from './UnverifiedChain.js';
import { DatePeriod } from './DatePeriod.js';
import { IANA_TRUST_ANCHORS } from './ianaTrustAnchors.js';
import type { TrustAnchor } from './TrustAnchor.js';
import { DsData } from './rdata/DsData.js';

function convertTrustAnchors(trustAnchors: readonly TrustAnchor[]): readonly DsData[] {
  return trustAnchors.map(
    (anchor) => new DsData(anchor.keyTag, anchor.algorithm, anchor.digestType, anchor.digest),
  );
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

  const dateOrPeriod = options.dateOrPeriod ?? new Date();
  const datePeriod =
    dateOrPeriod instanceof DatePeriod ? dateOrPeriod : DatePeriod.init(dateOrPeriod, dateOrPeriod);
  const dsData = options.trustAnchors
    ? convertTrustAnchors(options.trustAnchors)
    : IANA_TRUST_ANCHORS;
  return unverifiedChain.verify(datePeriod, dsData);
}
