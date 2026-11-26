"""Checks the reference client against the test vectors and against a real relay.

    uv run --with pynacl --with pytest pytest examples/

The end-to-end tests start the Node relay from ../relay on a free port.
"""
import copy
import json
import os
import pathlib
import socket
import subprocess
import time

import pytest

import bonvoyage as bv

ROOT = pathlib.Path(__file__).parent.parent
V = json.loads((ROOT / "vectors" / "v1.json").read_text(encoding="utf-8"))
NOW = V["now"]


def ident(who: dict) -> dict:
    return {"relay": who["address"].split("@")[1], "name": who["name"], "sign": who["signing_secret_seed"],
            "enc": who["encryption_secret"], "contacts": {}, "seen": {}}


def recipient_with_contact() -> dict:
    """The recipient as it is after issuing `cards.valid` to someone it calls "Kaj van het werk"."""
    me = ident(V["recipient"])
    card = V["cards"]["valid"]
    me["contacts"][V["drop_token"]["token_id"]] = {"name": "Kaj van het werk", "pair": card["pairing_secret"],
                                                   "expires": card["expires"], "key": None}
    return me


# --- vectors -------------------------------------------------------------------

def test_keys_addresses_and_tokens():
    for who in (V["sender"], V["recipient"], V["stranger"]):
        me = ident(who)
        assert bv.inbox_id(me) == who["inbox_id"] == who["signing_public"]
        assert bv.address(me) == who["address"]
    assert bv.token_id(bv.unb64(V["drop_token"]["token"])) == V["drop_token"]["token_id"]


def test_base64url_is_canonical():
    case = V["base64url"]
    assert bv.unb64(case["canonical"]["text"]).hex() == case["canonical"]["bytes_hex"]
    for bad in case["must_reject"]:
        with pytest.raises(bv.Discard):
            bv.unb64(bad)


def test_card_round_trip_and_signature():
    card = V["cards"]["valid"]
    me = ident(V["recipient"])
    uri = bv.make_card(me, bv.unb64(card["drop_token"]), bv.unb64(card["pairing_secret"]), expires=card["expires"])
    assert uri == card["uri"]
    parsed = bv.parse_card(card["uri"])
    assert parsed["address"] == V["recipient"]["address"] and parsed["name"] == card["name"]
    assert bv.b64(parsed["key"]) == card["encryption_key"] == V["recipient"]["encryption_public"]
    assert (parsed["token"], parsed["pair"], parsed["expires"]) == (card["drop_token"], card["pairing_secret"], card["expires"])


@pytest.mark.parametrize("name", list(V["cards"]["must_reject"]))
def test_bad_cards_are_refused(name):
    with pytest.raises(bv.Discard):
        bv.parse_card(V["cards"]["must_reject"][name])


def test_open_the_vector_message():
    m = V["message"]
    key, message = bv.open_message(ident(V["recipient"]), bv.unb64(m["sealed"]), now=NOW)
    assert message == json.loads(m["message_json"])
    assert bv.b64(key) == V["sender"]["signing_public"] and message["pair"] == V["cards"]["valid"]["pairing_secret"]
    assert bv.render_text(message["ticket"]) == m["expect_plain_text"]
    assert len(bv.unb64(m["sealed"])) == m["sealed_length"] == m["padded_length"] + 48
    assert m["padded_length"] % 4096 == 0


def test_signing_reproduces_the_vector():
    m = V["message"]
    message = json.loads(m["message_json"])
    card = bv.parse_card(V["cards"]["valid"]["uri"])
    sealed = bv.seal_message(ident(V["sender"]), card, message["ticket"], now=message["created"], message_id=bv.unb64(message["id"]))
    from nacl.public import PrivateKey, SealedBox
    padded = SealedBox(PrivateKey(bv.unb64(V["recipient"]["encryption_secret"]))).decrypt(sealed)
    assert padded[4:4 + int.from_bytes(padded[:4], "big")].decode() == m["signed_message_json"]


@pytest.mark.parametrize("name", list(V["must_reject"]))
def test_must_reject(name):
    with pytest.raises(bv.Discard):
        bv.open_message(ident(V["recipient"]), bv.unb64(V["must_reject"][name]), now=NOW)


def test_someone_else_cannot_open_it():
    with pytest.raises(bv.Discard):
        bv.open_message(ident(V["sender"]), bv.unb64(V["message"]["sealed"]), now=NOW)


def test_contact_checks_in_order():
    me = recipient_with_contact()
    for step in V["contact_checks"]["steps"]:
        outcome = "discard"
        try:
            key, message = bv.open_message(me, bv.unb64(step["sealed"]), now=NOW)
            seen = f"{bv.b64(key)}:{message['id']}"
            if seen in me["seen"]:
                raise bv.Discard("repeat")
            contact, paired = bv.find_contact(me, key, message["pair"], NOW)
            me["seen"][seen] = NOW
            if paired:
                contact["key"] = bv.b64(key)
            if message["type"] == "ticket":
                bv.validate_ticket(message["ticket"])
                outcome = "print"
        except bv.Discard:
            pass
        assert outcome == step["expect"], step["why"]
    assert next(iter(me["contacts"].values()))["key"] == V["sender"]["signing_public"]


def test_expired_card_cannot_pair():
    me = recipient_with_contact()
    key, message = bv.open_message(me, bv.unb64(V["message"]["sealed"]), now=NOW)
    with pytest.raises(bv.Discard, match="expired"):
        bv.find_contact(me, key, message["pair"], V["cards"]["valid"]["expires"] + 1)


@pytest.mark.parametrize("name", list(V["tickets"]["valid"]))
def test_valid_tickets(name):
    ticket = V["tickets"]["valid"][name]
    bv.validate_ticket(ticket)
    assert isinstance(bv.render_text(ticket), str)


@pytest.mark.parametrize("name", list(V["tickets"]["must_discard"]))
def test_tickets_over_a_limit_are_discarded(name):
    with pytest.raises(bv.Discard):
        bv.validate_ticket(V["tickets"]["must_discard"][name])


def test_text_cleaning():
    first, second = V["tickets"]["text_cleaning"]
    assert bv.clean_text(first["input"], keep_line_feeds=True) == first["output"]
    assert bv.clean_text(second["input"]) == second["output"]
    rendered = bv.render_text({"blocks": [{"type": "text", "text": first["input"]}, {"type": "list", "items": [second["input"]]}]})
    assert all(ch == "\n" or ch >= " " for ch in rendered), "no control characters survive"


def test_a_long_ticket_is_cut_off_by_the_recipient():
    ticket = {"blocks": [{"type": "list", "items": ["x"] * 50}] * 6}
    bv.validate_ticket(ticket)
    lines = bv.render_text(ticket, max_lines=40).split("\n")
    assert len(lines) == 41 and "cut off" in lines[-1]


def test_owner_request_header():
    r = V["owner_request"]
    from nacl.signing import SigningKey
    sig = SigningKey(bv.unb64(V["recipient"]["signing_secret_seed"])).sign(r["signing_input"].encode()).signature
    assert f"t={r['time']},sig={bv.b64(sig)}" == r["header"]
    assert r["signing_input"].split("\n")[2] == r["host"], "the relay host is part of what is signed"


# --- end to end through a real relay ---------------------------------------------

@pytest.fixture
def relay(tmp_path, monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "PORT": str(port), "BONVOYAGE_DB": str(tmp_path / "relay.db")}
    process = subprocess.Popen(["node", "src/server.js"], cwd=ROOT / "relay", env=env, stdout=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    monkeypatch.setenv("BONVOYAGE_DEV", "1")  # plain HTTP to localhost, for this test only
    yield f"localhost:{port}"
    process.terminate()


TICKET = {"blocks": [{"type": "text", "text": "Welkom bij de club!"}, {"type": "list", "items": ["koffie", "taart"], "style": "check"}]}


def test_two_printers_through_a_relay(relay):
    kaj, jan, eve = (bv.new_identity(relay, n) for n in ("Kaj", "Jan", "Eve"))
    for who in (kaj, jan, eve):
        bv.register(who)

    card = bv.parse_card(bv.issue_card(jan, "Kaj van het werk"))
    bv.register(jan)
    saves = []
    sealed = bv.seal_message(kaj, card, TICKET)
    bv.drop(card, sealed)
    bv.drop(card, sealed)  # the relay delivers the same message twice

    got = bv.receive(jan, persist=lambda: saves.append(copy.deepcopy(jan["seen"])))
    assert [c["name"] for c, _ in got] == ["Kaj van het werk"], "labelled with OUR name; the duplicate is discarded"
    assert len(saves) == 1 and saves[0], "the message was recorded on disk before being handed over"
    assert bv.render_text(got[0][1]["ticket"]) == "Welkom bij de club!\n[ ] koffie\n[ ] taart"
    contact = next(iter(jan["contacts"].values()))
    assert contact["key"] == bv.inbox_id(kaj)
    assert bv.receive(jan) == [], "handled messages were deleted from the relay"

    # Eve got hold of the card: the relay accepts her drop, Jan's pinned key does not.
    bv.drop(card, bv.seal_message(eve, card, TICKET))
    assert bv.receive(jan) == []

    # A second message from Kaj still prints.
    bv.drop(card, bv.seal_message(kaj, card, TICKET))
    assert len(bv.receive(jan)) == 1

    # Jan removes the contact: the relay now refuses the card.
    jan["contacts"].clear()
    bv.register(jan)
    with pytest.raises(RuntimeError, match="401"):
        bv.drop(card, bv.seal_message(kaj, card, TICKET))


def test_a_poison_message_does_not_block_the_inbox(relay):
    kaj, jan = bv.new_identity(relay, "Kaj"), bv.new_identity(relay, "Jan")
    bv.register(kaj)
    card = bv.parse_card(bv.issue_card(jan, "Kaj"))
    bv.register(jan)
    for override in ({"from": 12345}, {"created": "soon"}, {"v": True}, {"ticket": {"blocks": ["x"]}}):
        bv.drop(card, bv.seal_message(kaj, card, TICKET, _override=override))
    bv.drop(card, bv.seal_message(kaj, card, {"blocks": [{"type": "list", "items": [""] * 51}]}))
    bv.drop(card, bv.seal_message(kaj, card, TICKET))
    got = bv.receive(jan)
    assert len(got) == 1, "the good ticket arrives; every bad message was discarded and deleted"
    assert bv.receive(jan) == []


def test_plain_http_needs_development_mode(monkeypatch):
    monkeypatch.delenv("BONVOYAGE_DEV", raising=False)
    assert bv._base("localhost:8787") == "https://localhost:8787"
    monkeypatch.setenv("BONVOYAGE_DEV", "1")
    assert bv._base("localhost:8787") == "http://localhost:8787"
    assert bv._base("relay.example") == "https://relay.example"
