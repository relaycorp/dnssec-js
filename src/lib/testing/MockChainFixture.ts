import { type Resolver } from '../Resolver.js';
import { type TrustAnchor } from '../TrustAnchor.js';
import { type Message } from '../dns/Message.js';

export interface MockChainFixture {
  readonly resolver: Resolver;
  readonly responses: readonly Message[];
  readonly trustAnchors: readonly TrustAnchor[];
}
