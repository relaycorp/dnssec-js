import { DNSSECChain } from './DNSSECChain';

describe('verify', () => {
  test('Foo', async () => {
    const chain = new DNSSECChain();

    await expect(chain.verify()).toReject();
  });
});
