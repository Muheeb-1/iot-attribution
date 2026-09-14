"""
The asset inventory, and the promise that some devices can never be blamed.

A phone and a housemate's laptop share the air with the lab. Both must be
named - an unnamed device fragments into a scatter of raw MACs and DHCP
addresses - but they play different roles, and these tests pin the difference:

  * the PHONE is pure background: never scored, never ranked, never attacked.
  * laptop-i3 is a SCORED CANDIDATE: the detector scores it and attribution may
    rank or blame it (a permanently-innocent, naturally-loud device), yet
    scenario.py must never actually attack it.

"Scored/blamable" and "attackable" are separate properties; the guarantee is
that laptop-i3 has the first and not the second.
"""

import networkx as nx
import pandas as pd
import pytest

from src import attribute, capture, scenario


PHONE = ("48:83:b4:19:b8:13", "192.168.0.177", "phone")
LAPTOP = ("2c:6d:c1:3e:7a:9c", "192.168.0.218", "laptop-i3")

# Both must RESOLVE to a friendly name...
NAMED_NON_SENSORS = [PHONE, LAPTOP]
# ...but only the phone is pure background (never scored); the laptop is a
# scored candidate. Every device here must still never be ATTACKED.
BACKGROUND_ADDRESSES = [PHONE]
SCORED_CANDIDATE_ADDRESSES = [LAPTOP]


# --------------------------------------------------------------------------
# They resolve to a friendly name
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mac,ip,name", NAMED_NON_SENSORS)
def test_background_devices_resolve_by_mac(mac, ip, name):
    assert capture.endpoint_name(mac, ip) == name
    assert capture.endpoint_name(mac, "") == name


@pytest.mark.parametrize("mac,ip,name", NAMED_NON_SENSORS)
def test_background_devices_resolve_by_ip_alone(mac, ip, name):
    """
    Both devices key on a real burned-in MAC now, but a DHCP lease can still
    move and a handset can be switched back to a private address. The IP
    fallback has to work on its own, or one address change silently drops the
    device back to being an anonymous stranger.
    """
    assert capture.endpoint_name("", ip) == name


def test_the_phones_old_randomised_address_no_longer_resolves():
    """
    The phone used to present a randomised MAC on a different lease. Those are
    retired: if either still mapped to "phone", a future device handed that
    recycled address would inherit the name - and with it the never-attackable
    exemption - without anyone choosing that.
    """
    assert capture.endpoint_name("46:bf:ec:fd:f8:c6", "") != "phone"
    assert capture.endpoint_name("", "192.168.0.106") != "phone"
    assert "46:bf:ec:fd:f8:c6" not in capture.MAC_TO_NAME
    assert "192.168.0.106" not in capture.IP_TO_NAME


def test_mac_keys_are_stored_the_way_tshark_writes_them():
    """
    These MACs were handed over as 46-BF-EC-FD-F8-C6. Stored in that shape they
    would never match a packet, and the device would stay unnamed with no error
    anywhere - so the table must hold the lowercase colon form.
    """
    for mac in capture.MAC_TO_NAME:
        assert mac == mac.lower()
        assert "-" not in mac
        assert len(mac.split(":")) == 6


# --------------------------------------------------------------------------
# They are never suspects
# --------------------------------------------------------------------------

def test_the_phone_is_background_and_not_a_suspect():
    """DEVICE_KINDS is the suspect list; being absent from it is the exclusion."""
    for _, _, name in BACKGROUND_ADDRESSES:
        assert name in capture.BACKGROUND
        assert name not in capture.DEVICE_KINDS


def test_laptop_i3_is_a_scored_candidate_not_background():
    """
    laptop-i3 was promoted out of BACKGROUND: the detector must score it and
    attribution must be allowed to rank it, so it belongs in DEVICE_KINDS.
    """
    assert "laptop-i3" in capture.DEVICE_KINDS
    assert "laptop-i3" not in capture.BACKGROUND
    assert "laptop-i3" not in capture.NEVER_ORIGIN
    assert capture.DEVICE_KINDS["laptop-i3"] == "laptop"   # not mistaken for a sensor


def test_a_scored_candidate_is_still_never_attackable():
    """The whole point: scorable/blamable, but scenario can never trigger it."""
    for _, _, name in SCORED_CANDIDATE_ADDRESSES:
        assert name not in scenario.ORIGINS
        assert name in scenario.NEVER_ATTACK
        with pytest.raises(ValueError):
            scenario.choose_origin(name, seed=None)


def test_nothing_is_both_a_suspect_and_never_an_origin():
    assert not (capture.NEVER_ORIGIN & set(capture.DEVICE_KINDS))


def test_never_origin_covers_infrastructure_and_background():
    assert capture.NEVER_ORIGIN == capture.INFRASTRUCTURE | capture.BACKGROUND


def test_every_never_origin_name_is_actually_resolvable():
    """
    An exclusion only bites if the device resolves to the excluded name. An
    unmapped phone arrives as a raw MAC, which is in no list at all, and the
    protection silently does not apply to it.
    """
    resolvable = set(capture.MAC_TO_NAME.values()) | set(capture.IP_TO_NAME.values())
    assert not (capture.NEVER_ORIGIN - resolvable)


def test_a_captured_run_lists_the_scored_candidate_but_not_the_phone(tmp_path):
    """device_names in the meta file is what the whole pipeline treats as the lab."""
    frame = pd.DataFrame(columns=capture.COLUMNS)
    _, _, meta = capture.save_run(
        frame, "test_bg_run", pcap_path="pcap/none.pcapng", data_dir=tmp_path,
    )
    for _, _, name in BACKGROUND_ADDRESSES:
        assert name not in meta["device_names"]
        assert name not in [d["name"] for d in meta["devices"]]
    for _, _, name in SCORED_CANDIDATE_ADDRESSES:
        assert name in meta["device_names"]
        assert name in [d["name"] for d in meta["devices"]]


# --------------------------------------------------------------------------
# scenario.py can never fire a trigger at one
# --------------------------------------------------------------------------

def test_scenario_cannot_choose_a_background_device_as_origin():
    for _, _, name in BACKGROUND_ADDRESSES:
        assert name not in scenario.ORIGINS
        with pytest.raises(ValueError):
            scenario.choose_origin(name, seed=None)


def test_scenario_random_pick_only_ever_lands_on_a_board():
    for seed in range(200):
        assert scenario.choose_origin(None, seed) in scenario.ORIGINS


def test_scenario_never_attack_matches_the_canonical_inventory():
    """
    scenario.py imports nothing, so it keeps its own copies of these lists.
    That duplication is only safe if it is checked. The relationships encode
    the new model: attackable implies scored, and never-attack is exactly
    everything that is not attackable.
    """
    all_named = (set(capture.DEVICE_KINDS)
                 | capture.INFRASTRUCTURE | capture.BACKGROUND)
    # every board we can attack is a scored suspect
    assert set(scenario.ORIGINS) <= set(capture.DEVICE_KINDS)
    # never-attack is precisely the named devices that are not attackable
    assert set(scenario.NEVER_ATTACK) == all_named - set(scenario.ORIGINS)
    # never-scored (capture.NEVER_ORIGIN) is a subset of never-attacked
    assert capture.NEVER_ORIGIN <= set(scenario.NEVER_ATTACK)
    # and the difference is exactly the scored-but-not-attackable devices
    assert (set(scenario.NEVER_ATTACK) - capture.NEVER_ORIGIN
            == set(capture.DEVICE_KINDS) - set(scenario.ORIGINS))


# --------------------------------------------------------------------------
# attribute.py can never rank one
# --------------------------------------------------------------------------

def _two_device_connections():
    """esp32-01 and laptop-i3 both chatting to the broker, for the tests below."""
    rows = []
    cid = 0
    for t in range(0, 1200, 60):
        for src in ("esp32-01", "laptop-i3", "phone"):
            rows.append(("C%05d" % cid, float(t), src, "broker", 1883, 1000, 500, 10))
            cid += 1
    return pd.DataFrame(rows, columns=capture.COLUMNS)


def test_attribute_refuses_to_rank_a_device_outside_the_given_inventory():
    """
    A device absent from device_names must never be ranked, even if handed an
    onset directly - which detect.py cannot currently produce. Here the phone
    is outside the lab passed in, so it must be dropped.
    """
    lab = ["esp32-01", "esp32-02", "esp32-03"]   # phone NOT in this inventory
    result = attribute.attribute(
        _two_device_connections(),
        {"esp32-01": 600.0, "phone": 60.0},
        lab,
        baseline_seconds=600.0,
    )
    assert "phone" not in result.ranking
    assert result.named != "phone"
    assert "phone" not in result.onsets
    assert set(result.ranking) <= set(lab)


def test_attribute_MAY_rank_laptop_i3_when_it_is_in_the_inventory():
    """
    The other half of the promotion: laptop-i3 is a scored candidate, so when
    it is in device_names and fires an onset it is allowed into the ranking.
    (It is innocent in reality; the guarantee is only that it CAN be ranked,
    which is what makes it a real competitor rather than a filtered ghost.)
    """
    lab = ["esp32-01", "laptop-i3"]
    result = attribute.attribute(
        _two_device_connections(),
        {"esp32-01": 600.0, "laptop-i3": 120.0},
        lab,
        baseline_seconds=600.0,
    )
    assert "laptop-i3" in result.ranking
    assert set(result.ranking) <= set(lab)


def test_attribute_returns_nothing_when_only_background_devices_fired():
    """
    The phone going odd is not an incident. If it is the only thing that
    fired, the honest answer is no answer - not "the phone did it".
    """
    connections = pd.DataFrame(
        [("C00001", 10.0, "phone", "broker", 1883, 1000, 500, 10)],
        columns=capture.COLUMNS,
    )
    result = attribute.attribute(
        connections, {"phone": 60.0}, ["esp32-01", "esp32-02"],
        baseline_seconds=600.0,
    )
    assert result.ranking == []
    assert result.named is None
