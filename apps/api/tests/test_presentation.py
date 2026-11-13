from threatsight_api.decisions.project import explain
from threatsight_api.presentation import public_match, public_name


def test_public_names_hide_fixture_keys():
    assert public_name("synthetic.fixture:device:exact-widget") == "ordering-widget"
    assert public_name("meraki.dashboard:device:meraki-ap") == "privileged-access-gateway"
    assert public_name("junos.device:device:junos-edge") == "remote-access-vpn-oslo"
    assert public_name("junos.device:device:junos-edge:software") == "remote-access-vpn-oslo 23.4R1-synth"
    assert ":software" not in public_name("junos.device:device:junos-edge:software")
    assert public_name("device:exact-widget") == "ordering-widget"
    assert "synthetic.fixture" not in public_name("synthetic.fixture:device:unknown-box")


def test_unknown_match_state_is_safe():
    assert public_match("confirmed_identifier_match") == "Identifier match"
    assert public_match("not_a_state") == "Unknown state"


def test_explanation_uses_public_language():
    text = explain(
        "investigation_required",
        service="Customer ordering",
        live=[],
        reference=[{"match_state": "confirmed_identifier_match", "asset_label": "synthetic.fixture:device:exact-widget"}],
        paths=[{"id": "1"}],
        control_gap="No control record names this service.",
    )
    assert "Identifier match" in text
    assert "ordering-widget" in text
    assert "confirmed_identifier_match" not in text
    assert "synthetic.fixture" not in text
    unknown = explain(
        "investigation_required",
        service="Remote access",
        live=[],
        reference=[{"match_state": "unknown", "asset_label": "junos.device:device:junos-edge:software"}],
        paths=[],
        control_gap="Configured, not observed.",
    )
    assert "remote-access-vpn-oslo 23.4R1-synth" in unknown
    assert ":software" not in unknown
    assert "applicability is unknown" in unknown
