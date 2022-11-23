import { SecurityStatus } from './SecurityStatus';
import { RRSet } from './dns/RRSet';

interface BaseResult {
  readonly status: SecurityStatus;
}

export interface SuccessfulResult<R> extends BaseResult {
  readonly status: SecurityStatus.SECURE;
  readonly result: R;
}

export interface FailureResult extends BaseResult {
  readonly status: SecurityStatus.INSECURE | SecurityStatus.BOGUS | SecurityStatus.INDETERMINATE;
  readonly reasonChain: readonly string[];
}

export type VerificationResult<R = void> = SuccessfulResult<R> | FailureResult;

export type VerifiedRRSet = SuccessfulResult<RRSet>;
export type ChainVerificationResult = VerifiedRRSet | FailureResult;

export function augmentFailureResult(
  originalResult: FailureResult,
  additionalReason: string,
): FailureResult {
  return {
    status: originalResult.status,
    reasonChain: [additionalReason, ...originalResult.reasonChain],
  };
}
