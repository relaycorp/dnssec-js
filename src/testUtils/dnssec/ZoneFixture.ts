import { ZoneSigner } from '../../lib/signing/ZoneSigner';
import { DnskeyResponse, DsResponse } from '../../lib/signing/responses';

export interface ZoneFixture {
  readonly signer: ZoneSigner;
  readonly dsResponse: DsResponse;
  readonly dnskeyResponse: DnskeyResponse;
}
