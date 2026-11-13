const NAMES: Record<string, string> = {
  "synthetic.fixture:device:exact-widget": "ordering-widget",
  "device:exact-widget": "ordering-widget",
  "meraki.dashboard:device:meraki-ap": "privileged-access-gateway",
  "device:meraki-ap": "privileged-access-gateway",
  "junos.device:device:junos-edge:software": "remote-access-vpn-oslo 23.4R1-synth",
  "junos.device:device:junos-edge": "remote-access-vpn-oslo",
  "device:junos-edge": "remote-access-vpn-oslo",
  confirmed_identifier_match: "Identifier match",
  version_supported_candidate: "Version-supported candidate",
  possible_match: "Possible match",
};

export function scrubReferenceText(value: string): string {
  let text = value;
  const ordered = Object.entries(NAMES).sort((left, right) => right[0].length - left[0].length);
  for (const [key, label] of ordered) {
    text = text.replaceAll(key, label);
  }
  return text;
}
