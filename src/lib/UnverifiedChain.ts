import { Question } from './dns/Question';
import { Message } from './dns/Message';
import { DnssecRecordType } from './DnssecRecordType';
import { VerificationOptions } from './VerificationOptions';
import { augmentFailureResult, ChainVerificationResult } from './results';
import { SecurityStatus } from './SecurityStatus';
import { Zone } from './Zone';
import { DatePeriod } from './DatePeriod';
import { IANA_TRUST_ANCHORS } from './IANA_TRUST_ANCHORS';
import { SignedRRSet } from './SignedRRSet';
import { Resolver } from './Resolver';
import { DnsClass } from './dns/ianaClasses';

interface MessageByKey {
  readonly [key: string]: Message;
}

type FinalResolver = (question: Question) => Promise<Message>;

export class UnverifiedChain {
  public static async retrieve(question: Question, resolver: Resolver): Promise<UnverifiedChain> {
    const finalResolver: FinalResolver = async (q) => {
      const message = await resolver(q);
      return message instanceof Message ? message : Message.deserialise(message);
    };
    const zoneNames = getZonesInChain(question.name);
    const dnskeyMessages = await retrieveZoneMessages(
      zoneNames,
      DnssecRecordType.DNSKEY,
      question.class_,
      finalResolver,
    );
    const dsMessages = await retrieveZoneMessages(
      zoneNames.slice(1), // Skip the root DS
      DnssecRecordType.DS,
      question.class_,
      finalResolver,
    );
    const zoneMessageByKey: MessageByKey = { ...dnskeyMessages, ...dsMessages };
    const response = await finalResolver(question);
    return new UnverifiedChain(question, response, zoneMessageByKey);
  }

  public static initFromMessages(query: Question, messages: readonly Message[]): UnverifiedChain {
    const allMessages = messages.reduce((acc, m) => {
      const question = m.questions[0];
      if (!question) {
        return acc;
      }
      const key = question.key;
      return { ...acc, [key]: m };
    }, {} as MessageByKey);
    const zoneNames = getZonesInChain(query.name);
    const messageByKey = zoneNames.reduce((acc, zoneName) => {
      const dsKey = `${zoneName}/${DnssecRecordType.DS}`;
      const dsMessage = zoneName === '.' ? null : allMessages[dsKey];
      const dnskeyKey = `${zoneName}/${DnssecRecordType.DNSKEY}`;
      const dnskeyMessage = allMessages[dnskeyKey];
      return {
        ...acc,
        ...(dsMessage ? { [dsKey]: dsMessage } : {}),
        ...(dnskeyMessage ? { [dnskeyKey]: dnskeyMessage } : {}),
      };
    }, {} as MessageByKey);

    const queryResponse = allMessages[query.key];
    if (!queryResponse) {
      throw new Error(`At least one message must answer ${query.key}`);
    }

    return new UnverifiedChain(query, queryResponse, messageByKey);
  }

  protected constructor(
    public readonly query: Question,
    public readonly response: Message,
    public readonly zoneMessageByKey: MessageByKey,
  ) {}

  public verify(options: Partial<VerificationOptions> = {}): ChainVerificationResult {
    const rootDnskeyMessage = this.zoneMessageByKey[`./${DnssecRecordType.DNSKEY}`];
    if (!rootDnskeyMessage) {
      return {
        status: SecurityStatus.INDETERMINATE,
        reasonChain: ['Cannot initialise root zone without a DNSKEY response'],
      };
    }
    const dateOrPeriod = options.dateOrPeriod ?? new Date();
    const datePeriod =
      dateOrPeriod instanceof DatePeriod
        ? dateOrPeriod
        : DatePeriod.init(dateOrPeriod, dateOrPeriod);
    const rootDsData = options.trustAnchors ?? IANA_TRUST_ANCHORS;
    const rootZoneResult = Zone.initRoot(rootDnskeyMessage, rootDsData, datePeriod);
    if (rootZoneResult.status !== SecurityStatus.SECURE) {
      return augmentFailureResult(rootZoneResult, 'Got invalid DNSKEY for root zone');
    }
    const rootZone = rootZoneResult.result;

    let zones = [rootZone];
    for (const zoneName of getZonesInChain(this.query.name, false)) {
      const zoneDnskeyMessage = this.zoneMessageByKey[`${zoneName}/${DnssecRecordType.DNSKEY}`];
      if (!zoneDnskeyMessage) {
        return {
          status: SecurityStatus.INDETERMINATE,
          reasonChain: [`Cannot verify zone ${zoneName} without a DNSKEY response`],
        };
      }
      const zoneDsMessage = this.zoneMessageByKey[`${zoneName}/${DnssecRecordType.DS}`];
      if (!zoneDsMessage) {
        return {
          status: SecurityStatus.INDETERMINATE,
          reasonChain: [`Cannot verify zone ${zoneName} without a DS response`],
        };
      }
      const parent = zones[zones.length - 1];
      const zoneResult = parent.initChild(zoneName, zoneDnskeyMessage, zoneDsMessage, datePeriod);
      if (zoneResult.status !== SecurityStatus.SECURE) {
        return augmentFailureResult(zoneResult, `Failed to verify zone ${zoneName}`);
      }
      const zone = zoneResult.result;

      zones = [...zones, zone];
    }

    const apexZone = zones[zones.length - 1];
    const answers = SignedRRSet.initFromRecords(this.query, this.response.answers);
    if (!apexZone.verifyRrset(answers, datePeriod)) {
      return {
        status: SecurityStatus.BOGUS,
        reasonChain: ['Query response does not have a valid signature'],
      };
    }

    return {
      status: SecurityStatus.SECURE,
      result: answers.rrset,
    };
  }
}

function getZonesInChain(zoneName: string, includeRoot: boolean = true): readonly string[] {
  if (zoneName === '') {
    return includeRoot ? ['.'] : [];
  }
  const parentZoneName = zoneName.replace(/^[^.]+\./, '');
  const parentZones = getZonesInChain(parentZoneName, includeRoot);
  return [...parentZones, zoneName];
}

async function retrieveZoneMessages(
  zoneNames: readonly string[],
  recordType: DnssecRecordType,
  class_: DnsClass,
  resolver: FinalResolver,
): Promise<MessageByKey> {
  const question = new Question('.', recordType, class_);
  return zoneNames.reduce(async (messages, zoneName) => {
    const message = await resolver(question.shallowCopy({ name: zoneName }));
    return { ...(await messages), [`${zoneName}/${recordType}`]: message };
  }, Promise.resolve({} as MessageByKey));
}
