/* eslint-disable @typescript-eslint/no-magic-numbers */
import { addMinutes } from 'date-fns';

import { ZoneSigner } from '../utils/dnssec/ZoneSigner.js';
import { getZonesInChain } from '../utils/dns.js';
import { DnssecAlgorithm } from '../DnssecAlgorithm.js';
import { type RrSet } from '../dns/RrSet.js';
import { type DatePeriod } from '../DatePeriod.js';
import { type SignatureOptions } from '../utils/dnssec/SignatureOptions.js';
import { type ZoneResponseSet } from '../utils/dnssec/responses.js';
import { Message } from '../dns/Message.js';
import { type Resolver } from '../Resolver.js';
import { type DsData } from '../rdata/DsData.js';
import { type TrustAnchor } from '../TrustAnchor.js';
import { SecurityStatus } from '../SecurityStatus.js';
import { RCODE_IDS } from '../dns/ianaRcodes.js';

import { type MockChainFixture } from './MockChainFixture.js';

export class MockChain {
  public static async generate(zoneName: string): Promise<MockChain> {
    const zoneNames = getZonesInChain(zoneName);
    const signers = await Promise.all(
      zoneNames.map(async (name) => ZoneSigner.generate(DnssecAlgorithm.RSASHA256, name)),
    );
    return new MockChain(signers);
  }

  protected constructor(protected readonly signers: readonly ZoneSigner[]) {}

  protected generateZoneResponses(signatureOptions: SignatureOptions): readonly ZoneResponseSet[] {
    const [rootSigner] = this.signers;
    let parentSigner = rootSigner;
    let parentDnskeyTag: number | null = null;
    return this.signers.map((signer) => {
      const zoneResponses = signer.generateZoneResponses(parentSigner, parentDnskeyTag, {
        dnskey: signatureOptions,
        ds: signatureOptions,
      });
      parentSigner = signer;
      parentDnskeyTag = zoneResponses.ds.data.keyTag;
      return zoneResponses;
    });
  }

  protected generateResolver(
    responsesByZone: readonly ZoneResponseSet[],
    status: SecurityStatus,
    rrset: RrSet,
    signatureOptions: SignatureOptions,
  ): Resolver {
    const apexResponses = responsesByZone.at(-1);
    const apexDsMessage = apexResponses!.ds;
    const apexSigner = this.signers.at(-1);

    const zoneResponses = responsesByZone.flatMap((set) => [set.ds.message, set.dnskey.message]);
    let responses: readonly Message[];
    switch (status) {
      case SecurityStatus.INSECURE: {
        const rrsig = apexSigner!.generateRrsig(rrset, apexDsMessage.data.keyTag, signatureOptions);
        responses = [
          ...zoneResponses.map((response) =>
            response === apexDsMessage.message
              ? new Message({ rcode: RCODE_IDS.NXDOMAIN }, response.questions, [])
              : response,
          ),
          rrsig.message,
        ];
        break;
      }
      case SecurityStatus.BOGUS: {
        const invalidKeyTag = Math.ceil(apexDsMessage.data.keyTag / 2) + 2;
        const rrsig = apexSigner!.generateRrsig(rrset, invalidKeyTag, signatureOptions);
        responses = [...zoneResponses, rrsig.message];
        break;
      }
      case SecurityStatus.INDETERMINATE: {
        const rrsig = apexSigner!.generateRrsig(rrset, apexDsMessage.data.keyTag, signatureOptions);
        responses = [
          ...zoneResponses.filter((response) => response !== apexDsMessage.message),
          rrsig.message,
        ];
        break;
      }
      default: {
        const rrsig = apexSigner!.generateRrsig(rrset, apexDsMessage.data.keyTag, signatureOptions);
        responses = [...zoneResponses, rrsig.message];
        break;
      }
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    return async (question) => responses.find((response) => response.answersQuestion(question))!;
  }

  protected generateTrustAnchors(dsData: DsData): readonly TrustAnchor[] {
    return [
      {
        keyTag: dsData.keyTag,
        algorithm: dsData.algorithm,
        digestType: dsData.digestType,
        digest: dsData.digest,
      },
    ];
  }

  public generateFixture(
    rrset: RrSet,
    status: SecurityStatus,
    signaturePeriod?: DatePeriod,
  ): MockChainFixture {
    const now = new Date();
    const signatureOptions: SignatureOptions = signaturePeriod
      ? { signatureInception: signaturePeriod.start, signatureExpiry: signaturePeriod.end }
      : { signatureInception: now, signatureExpiry: addMinutes(now, 1) };
    const responsesByZone = this.generateZoneResponses(signatureOptions);

    const resolver = this.generateResolver(responsesByZone, status, rrset, signatureOptions);
    const rootResponses = responsesByZone.at(0);
    const trustAnchors = this.generateTrustAnchors(rootResponses!.ds.data);
    return { resolver, trustAnchors };
  }
}
