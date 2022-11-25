import type { FailureResult } from './results';
import { augmentFailureResult } from './results';
import { SecurityStatus } from './SecurityStatus';

describe('augmentFailureResult', () => {
  const ORIGINAL_RESULT: FailureResult = {
    reasonChain: ['Whoops'],
    status: SecurityStatus.INDETERMINATE,
  };

  const ADDITIONAL_REASON = 'Oh noes';

  test('Original status should be preserved', () => {
    const newResult = augmentFailureResult(ORIGINAL_RESULT, ADDITIONAL_REASON);

    expect(newResult.status).toEqual(ORIGINAL_RESULT.status);
  });

  test('New reason should be added to the beginning', () => {
    const newResult = augmentFailureResult(ORIGINAL_RESULT, ADDITIONAL_REASON);

    expect(newResult.reasonChain).toHaveLength(ORIGINAL_RESULT.reasonChain.length + 1);
    expect(newResult.reasonChain[0]).toEqual(ADDITIONAL_REASON);
  });
});
