import { type Resolver } from '../Resolver.js';
import { type TrustAnchor } from '../TrustAnchor.js';

export interface MockChainFixture {
  readonly resolver: Resolver;
  readonly trustAnchors: readonly TrustAnchor[];
}
