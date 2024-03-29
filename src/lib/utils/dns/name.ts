export function serialiseName(name: string): Buffer {
  if (name === '.') {
    return Buffer.alloc(1);
  }
  const labels = name
    .replace(/\.$/u, '')
    .split('.')
    .map((label) => {
      const labelSerialised = Buffer.from(label);
      const lengthPrefix = Buffer.from([labelSerialised.byteLength]);
      return Buffer.concat([lengthPrefix, labelSerialised]);
    });
  return Buffer.concat([...labels, Buffer.alloc(1)]);
}

export function normaliseName(name: string): string {
  return name.endsWith('.') ? name : `${name}.`;
}

export function countLabels(name: string): number {
  const nameWithoutTrailingDot = name.replace(/\.$/u, '');
  if (nameWithoutTrailingDot === '') {
    return 0;
  }
  const labels = nameWithoutTrailingDot.split('.').filter((label) => label !== '*');
  return labels.length;
}

export function isChildZone(parentName: string, presumedChildName: string): boolean {
  if (parentName === '.') {
    return true;
  }
  return presumedChildName.endsWith(`.${parentName}`);
}

export function getZonesInName(zoneName: string, shouldIncludeRoot = true): readonly string[] {
  if (zoneName === '') {
    return shouldIncludeRoot ? ['.'] : [];
  }
  const parentZoneName = zoneName.replace(/^[^.]+\./u, '');
  const parentZones = getZonesInName(parentZoneName, shouldIncludeRoot);
  return [...parentZones, zoneName];
}
