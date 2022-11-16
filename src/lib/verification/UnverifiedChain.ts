import { Question } from '../dns/Question';
import { Message } from '../dns/Message';
import { DnssecRecordType } from '../DnssecRecordType';

interface MessageByKey {
  readonly [name: string]: Message;
}

export class UnverifiedChain {
  // public static async retrieve(
  //   question: Omit<Question, 'class'>,
  //   resolver: (q: Question) => Promise<Message>,
  // ): Promise<UnverifiedChain> {
  //   throw new Error('' + question + resolver);
  // }

  public static initFromMessages(
    question: Question,
    messages: readonly Message[],
  ): UnverifiedChain {
    const allMessages = messages.reduce((acc, m) => {
      const question = m.questions[0];
      if (!question) {
        return acc;
      }
      const key = question.key;
      return { ...acc, [key]: m };
    }, {} as MessageByKey);
    const zoneNames = getZonesInChain(question.name);
    const zoneMessageByKey = zoneNames.reduce((acc, zoneName) => {
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

    const queryResponse = allMessages[question.key];
    const messageByKey = {
      ...zoneMessageByKey,
      ...(queryResponse ? { [question.key]: queryResponse } : {}),
    };

    return new UnverifiedChain(messageByKey, question);
  }

  protected constructor(
    public readonly messageByKey: MessageByKey,
    public readonly question: Question,
  ) {}

  // public verify(
  //   _dateOrPeriod: Date | DatePeriod = new Date(),
  //   _trustAnchors: readonly DsData[] = TRUST_ANCHORS,
  // ): VerificationResult<RRSet> {
  //   throw new Error('Implement');
  // }
}

function getZonesInChain(zoneName: string): readonly string[] {
  if (zoneName === '') {
    return ['.'];
  }
  const parentZoneName = zoneName.replace(/^[^.]+\./, '');
  const parentZones = getZonesInChain(parentZoneName);
  return [zoneName, ...parentZones];
}
