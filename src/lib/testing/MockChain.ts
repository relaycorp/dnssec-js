/* eslint-disable @typescript-eslint/no-magic-numbers */
import { addMinutes } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm.js';
import { type RrSet } from '../utils/dns/RrSet.js';
import { type DatePeriod } from '../DatePeriod.js';
import { type DsResponse, type ZoneResponseSet } from '../dnssecResponses.js';
import { Message } from '../utils/dns/Message.js';
import { type Resolver } from '../Resolver.js';
import { type DsData } from '../records/DsData.js';
import { type TrustAnchor } from '../TrustAnchor.js';
import { SecurityStatus } from '../SecurityStatus.js';
import { RCODE_IDS } from '../utils/dns/ianaRcodes.js';
import { getZonesInName } from '../utils/dns/name.js';

import { type MockChainFixture } from './MockChainFixture.js';
import { type SignatureOptions } from './SignatureOptions.js';
import { ZoneSigner } from './ZoneSigner.js';

export class MockChain {
  public static async generate(zoneName: string): Promise<MockChain> {
    const zoneNames = getZonesInName(zoneName);
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

  private generateBogusResponses(
    rrset: RrSet,
    zoneResponses: Message[],
    apexDs: DsResponse,
    apexSigner: ZoneSigner,
    signatureOptions: SignatureOptions,
  ) {
    const invalidKeyTag = Math.ceil(apexDs.data.keyTag / 2) + 2;
    const rrsig = apexSigner.generateRrsig(rrset, invalidKeyTag, signatureOptions);
    return [...zoneResponses, rrsig.message];
  }

  private generateInsecureResponses(
    rrset: RrSet,
    zoneResponses: Message[],
    apexSigner: ZoneSigner,
    apexDs: DsResponse,
    signatureOptions: SignatureOptions,
  ) {
    const rrsig = apexSigner.generateRrsig(rrset, apexDs.data.keyTag, signatureOptions);
    return [
      ...zoneResponses.map((response) =>
        response === apexDs.message
          ? new Message({ rcode: RCODE_IDS.NXDOMAIN }, response.questions, [])
          : response,
      ),
      rrsig.message,
    ];
  }

  private generateIndeterminateResponses(
    rrset: RrSet,
    zoneResponses: Message[],
    apexSigner: ZoneSigner,
    apexDs: DsResponse,
    apexResponses: ZoneResponseSet | undefined,
    signatureOptions: SignatureOptions,
  ) {
    const rrsig = apexSigner.generateRrsig(rrset, apexDs.data.keyTag, signatureOptions);
    const apexDnskey = apexResponses!.dnskey;
    const unsignedApexDnskeyMessage = new Message(
      apexDnskey.message.header,
      apexDnskey.message.questions,
      [apexDnskey.record],
    );
    return [
      ...zoneResponses.filter((response) => response !== apexDnskey.message),
      unsignedApexDnskeyMessage,
      rrsig.message,
    ];
  }

  private generateSecureResponses(
    rrset: RrSet,
    zoneResponses: Message[],
    apexSigner: ZoneSigner,
    apexDs: DsResponse,
    signatureOptions: SignatureOptions,
  ) {
    const rrsig = apexSigner.generateRrsig(rrset, apexDs.data.keyTag, signatureOptions);
    return [...zoneResponses, rrsig.message];
  }

  private generateResponses(
    responsesByZone: readonly ZoneResponseSet[],
    status: SecurityStatus,
    rrset: RrSet,
    signatureOptions: SignatureOptions,
  ) {
    const apexResponses = responsesByZone.at(-1);
    const apexDs = apexResponses!.ds;
    const apexSigner = this.signers.at(-1)!;
    const zoneResponses = responsesByZone.flatMap((set) => [set.ds.message, set.dnskey.message]);
    let responses: readonly Message[];
    switch (status) {
      case SecurityStatus.INSECURE: {
        responses = this.generateInsecureResponses(
          rrset,
          zoneResponses,
          apexSigner,
          apexDs,
          signatureOptions,
        );
        break;
      }
      case SecurityStatus.BOGUS: {
        responses = this.generateBogusResponses(
          rrset,
          zoneResponses,
          apexDs,
          apexSigner,
          signatureOptions,
        );
        break;
      }
      case SecurityStatus.INDETERMINATE: {
        responses = this.generateIndeterminateResponses(
          rrset,
          zoneResponses,
          apexSigner,
          apexDs,
          apexResponses,
          signatureOptions,
        );
        break;
      }
      default: {
        responses = this.generateSecureResponses(
          rrset,
          zoneResponses,
          apexSigner,
          apexDs,
          signatureOptions,
        );
        break;
      }
    }
    return responses;
  }

  protected generateResolver(responses: readonly Message[]): Resolver {
    // eslint-disable-next-line @typescript-eslint/require-await
    return async (question) => {
      const matchingResponse = responses.find((response) => response.answersQuestion(question));
      return matchingResponse ?? new Message({ rcode: RCODE_IDS.NXDOMAIN }, [question], []);
    };
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

    const responses = this.generateResponses(responsesByZone, status, rrset, signatureOptions);
    const resolver = this.generateResolver(responses);
    const rootResponses = responsesByZone.at(0);
    const trustAnchors = this.generateTrustAnchors(rootResponses!.ds.data);
    return { resolver, trustAnchors, responses };
  }
}
