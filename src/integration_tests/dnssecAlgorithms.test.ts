import { addSeconds, subSeconds } from 'date-fns';

import { DnssecAlgorithm } from '../lib/DnssecAlgorithm';
import { SignatureGenerationOptions, ZoneSigner } from '../lib/signing/ZoneSigner';
import { Zone } from '../lib/verification/Zone';
import { DatePeriod } from '../lib/verification/DatePeriod';
import { SecurityStatus } from '../lib/verification/SecurityStatus';

const NOW = new Date();
const VALIDITY_PERIOD = DatePeriod.init(subSeconds(NOW, 1), addSeconds(NOW, 1));
const SIGNATURE_OPTIONS: SignatureGenerationOptions = {
  signatureExpiry: VALIDITY_PERIOD.end,
  signatureInception: VALIDITY_PERIOD.start,
};

describe('Support for DNSSEC algorithms', () => {
  test.each([DnssecAlgorithm.RSASHA1, DnssecAlgorithm.RSASHA256, DnssecAlgorithm.RSASHA512])(
    'Algorithm %s',
    async (algo) => {
      const rootSigner = await ZoneSigner.generate(algo, '.');
      const rootMessages = rootSigner.generateZoneResponses(rootSigner, null, {
        dnskey: SIGNATURE_OPTIONS,
        ds: SIGNATURE_OPTIONS,
      });

      const zoneResult = Zone.initRoot(
        rootMessages.dnskey.message,
        [rootMessages.ds.data],
        VALIDITY_PERIOD,
      );

      expect(zoneResult.status).toEqual(SecurityStatus.SECURE);
    },
  );
});
