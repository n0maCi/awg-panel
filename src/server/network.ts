function ipToNumber(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    throw new Error(`Некорректный IPv4-адрес: ${ip}`);
  }
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function numberToIp(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

export function splitCidr(cidr: string): { ip: string; prefix: number } {
  const [ip, prefixString] = cidr.split('/');
  const prefix = Number(prefixString);
  ipToNumber(ip);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`Некорректная подсеть: ${cidr}`);
  }
  return { ip, prefix };
}

export function networkCidr(cidr: string): string {
  const { ip, prefix } = splitCidr(cidr);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return `${numberToIp(ipToNumber(ip) & mask)}/${prefix}`;
}

export function allocateAddress(interfaceCidr: string, used: string[]): string {
  const { ip, prefix } = splitCidr(interfaceCidr);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = ipToNumber(ip) & mask;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const server = ipToNumber(ip);
  const occupied = new Set(used.map((item) => ipToNumber(item)));

  for (let candidate = network + 1; candidate < broadcast; candidate += 1) {
    const normalized = candidate >>> 0;
    if (normalized !== server && !occupied.has(normalized)) return numberToIp(normalized);
  }
  throw new Error('В подсети не осталось свободных адресов');
}

export function addressBelongsToCidr(address: string, cidr: string): boolean {
  const { ip, prefix } = splitCidr(cidr);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipToNumber(address) & mask) === (ipToNumber(ip) & mask);
}
