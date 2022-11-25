import type { SecurityStatus } from './SecurityStatus';
import type { RRSet } from './dns/RRSet';

interface BaseResult {
  readonly status: SecurityStatus;
}

export interface SuccessfulResult<R> extends BaseResult {
  readonly status: SecurityStatus.SECURE;
  readonly result: R;
}

export interface FailureResult extends BaseResult {
  readonly status: SecurityStatus.BOGUS | SecurityStatus.INDETERMINATE | SecurityStatus.INSECURE;
  readonly reasonChain: readonly string[];
}

export type VerificationResult<R = void> = FailureResult | SuccessfulResult<R>;

export type VerifiedRRSet = SuccessfulResult<RRSet>;
export type ChainVerificationResult = FailureResult | VerifiedRRSet;

export function augmentFailureResult(
  originalResult: FailureResult,
  additionalReason: string,
): FailureResult {
  return {
    status: originalResult.status,
    reasonChain: [additionalReason, ...originalResult.reasonChain],
  };
}
