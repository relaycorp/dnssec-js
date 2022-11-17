import { Parser } from 'binary-parser';

const LABEL_PARSER = new Parser().uint8('labelLength').string('label', { length: 'labelLength' });
export const NAME_PARSER_OPTIONS = {
  formatter(labels: any): string {
    const name = labels.map((label: any) => label.label).join('.');
    return name === '' ? '.' : name;
  },
  type: LABEL_PARSER,
  readUntil(lastItem: any): boolean {
    return lastItem.labelLength === 0;
  },
};

export function serialiseName(name: string): Buffer {
  if (name === '.') {
    return Buffer.alloc(1);
  }
  const labels = name
    .replace(/\.$/, '')
    .split('.')
    .map((label) => {
      const labelSerialised = Buffer.from(label);
      const lengthPrefix = Buffer.from([labelSerialised.byteLength]);
      return Buffer.concat([lengthPrefix, labelSerialised]);
    });
  return Buffer.concat([...labels, Buffer.alloc(1)]);
}
