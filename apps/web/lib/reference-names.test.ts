import assert from "node:assert/strict";
import test from "node:test";

import { scrubReferenceText } from "./reference-names.ts";
import { TRUTH, commercialTitle, maturityStatement, presentedValue, truthFor } from "./vocabulary.ts";

test("default copy does not keep fixture keys", () => {
  const text = scrubReferenceText("confirmed_identifier_match on synthetic.fixture:device:exact-widget");
  assert.equal(text.includes("synthetic.fixture"), false);
  assert.equal(text.includes("confirmed_identifier_match"), false);
  assert.match(text, /Identifier match/);
  assert.match(text, /ordering-widget/);
  const software = scrubReferenceText("junos.device:device:junos-edge:software");
  assert.equal(software, "remote-access-vpn-oslo 23.4R1-synth");
  assert.equal(software.includes(":software"), false);
  assert.equal(commercialTitle("Fixture Cisco Meraki advisory"), "Cisco Meraki advisory");
  assert.equal(presentedValue("credential_required"), "Credentials required");
  assert.equal(presentedValue("synthetic-correlation"), "Synthetic reference evidence");
  assert.equal(presentedValue("not_a_real_state"), "Unknown state");
  assert.equal(maturityStatement("fixture_tested"), "Validated with reference data. Tested against controlled synthetic data. A live customer environment has not been validated.");
  assert.equal(presentedValue("owner_not_assigned"), "Owner not assigned.");
  assert.equal(presentedValue("depends_on"), "Depends on");
  assert.equal(presentedValue("fresh"), "Fresh");
  assert.equal(presentedValue("VALIDATED"), "Validated");
  assert.equal(presentedValue("GAP_DETECTED"), "Gap detected");
  assert.equal(presentedValue("PASS"), "Passed defined check");
  assert.equal(presentedValue("EVIDENCE_REQUIRED"), "Evidence required");
  assert.equal(presentedValue("not_packet_delivery"), "A candidate path is not packet delivery.");
  assert.equal(truthFor("fixture_tested")?.label, "Validated with reference data");
  assert.match(truthFor("fixture_tested")?.description ?? "", /live customer environment has not been validated/i);
  assert.equal(truthFor("live_verified")?.label, "Live verified");
  assert.notEqual(TRUTH.fixture_tested.label, TRUTH.live_verified.label);
  assert.equal(truthFor("not_a_maturity"), null);
  assert.equal(presentedValue("not_a_maturity"), "Unknown state");
});
