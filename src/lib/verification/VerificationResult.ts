import { SecurityStatus } from './SecurityStatus';

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
