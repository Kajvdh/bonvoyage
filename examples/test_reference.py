"""Checks the reference client against the test vectors and against a real relay.

    uv run --with pynacl --with pytest pytest examples/

The end-to-end test starts the Node relay from ../relay on a free port.
"""
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


def ident(who: dict, relay: str) -> dict:
    return {"relay": relay, "name": who["name"], "sign": who["signing_secret_seed"], "enc": who["encryption_secret"],
            "contacts": {}, "seen": {}}


def test_keys_addresses_tokens_and_card():
    for who in (V["sender"], V["recipient"]):
        me = ident(who, who["address"].split("@")[1])
        assert bv.inbox_id(me) == who["inbox_id"] == who["signing_public"]
        assert bv.address(me) == who["address"]
    token = bv.unb64(V["drop_token"]["token"])
    assert bv.token_id(token) == V["drop_token"]["token_id"]
    recipient = ident(V["recipient"], "bonvoyage.example")
    assert bv.make_card(recipient, token) == V["contact_card"]["uri"]
    card = bv.parse_card(V["contact_card"]["uri"])
    assert card["address"] == V["recipient"]["address"] and card["name"] == "Jan"
    assert bv.b64(card["key"]) == V["recipient"]["encryption_public"]


def test_open_the_vector_message():
    recipient = ident(V["recipient"], "bonvoyage.example")
    m = V["message"]
    message = bv.open_message(recipient, bv.unb64(m["sealed"]), now=m["opened_at"])
    assert message == json.loads(m["message_json"])
    assert message["from"] == V["sender"]["address"] and message["from_name"] == "Kaj"
    assert bv.render_text(message["ticket"]) == m["expect_plain_text"]
    assert len(bv.unb64(m["sealed"])) == m["sealed_length"] == m["padded_length"] + 48
    assert m["padded_length"] % 4096 == 0


def test_signature_is_deterministic_and_matches():
    sender = ident(V["sender"], "relay.example")
    m = V["message"]
    message = json.loads(m["message_json"])
    sealed = bv.seal_message(sender, message["to"], bv.unb64(V["recipient"]["encryption_public"]), message["ticket"],
                             now=message["created"], message_id=bv.unb64(message["id"]))
    recipient = ident(V["recipient"], "bonvoyage.example")
    assert bv.open_message(recipient, sealed, now=m["opened_at"]) == message
    from nacl.public import PrivateKey, SealedBox
    padded = SealedBox(PrivateKey(bv.unb64(recipient["enc"]))).decrypt(sealed)
    assert padded[4:4 + int.from_bytes(padded[:4], "big")].decode() == m["signed_message_json"]


@pytest.mark.parametrize("name", [k for k in V["must_reject"] if k != "note"])
def test_must_reject(name):
    recipient = ident(V["recipient"], "bonvoyage.example")
    with pytest.raises(ValueError):
        bv.open_message(recipient, bv.unb64(V["must_reject"][name]), now=V["message"]["opened_at"])


def test_someone_else_cannot_open_it():
    with pytest.raises(ValueError):
        bv.open_message(ident(V["sender"], "relay.example"), bv.unb64(V["message"]["sealed"]), now=V["message"]["opened_at"])


@pytest.fixture
def relay(tmp_path):
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
    yield f"localhost:{port}"
    process.terminate()


def test_two_printers_through_a_relay(relay):
    kaj, jan, eve = (bv.new_identity(relay, n) for n in ("Kaj", "Jan", "Eve"))
    for who in (kaj, jan, eve):
        bv.register(who)

    token = os.urandom(32)
    jan["contacts"][bv.token_id(token)] = {"name": "Kaj"}
    bv.register(jan)
    card = bv.parse_card(bv.make_card(jan, token))

    ticket = {"blocks": [{"type": "text", "text": "Koffie om 10u?"}, {"type": "list", "items": ["ja", "nee"], "style": "check"}]}
    sealed = bv.seal_message(kaj, card["address"], card["key"], ticket)
    bv.drop(card, sealed)
    bv.drop(card, sealed)  # the relay delivers the same message twice

    got = bv.receive(jan)
    assert [(c["name"], m["from_name"]) for c, m in got] == [("Kaj", "Kaj")], "the duplicate is discarded"
    assert bv.render_text(got[0][1]["ticket"]) == "Koffie om 10u?\n[ ] ja\n[ ] nee"
    assert jan["contacts"][bv.token_id(token)]["pinned"] == bv.address(kaj)
    assert bv.receive(jan) == [], "handled messages were deleted from the relay"

    # Eve got hold of the card: the token works at the relay, but Jan pinned Kaj's key.
    bv.drop(card, bv.seal_message(eve, card["address"], card["key"], ticket))
    assert bv.receive(jan) == []

    # Jan removes the contact: the relay now refuses the card.
    jan["contacts"].clear()
    bv.register(jan)
    with pytest.raises(RuntimeError, match="401"):
        bv.drop(card, bv.seal_message(kaj, card["address"], card["key"], ticket))
