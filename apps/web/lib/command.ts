export function serviceFor(text: string): string {
  const value = text.toLowerCase();
  if (/fortinet|palo|cisco|vpn|firewall|pan-os|fortios|meraki/.test(value)) {
    return "Remote access and site connectivity";
  }
  if (/entra|identity|admin|privileged|azure/.test(value)) {
    return "Privileged administration";
  }
  return "Customer ordering";
}
