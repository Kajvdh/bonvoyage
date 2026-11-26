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
            "enc": who["encryption_secret"], "contacts": {}, "seen": {}, "queue": []}


def recipient_with_contact() -> dict:
    """The recipient as it is after issuing `cards.valid` to someone it calls "Kaj van het werk"."""
    me = ident(V["recipient"])
    contact = V["contact_checks"]["contact"]
    me["contacts"][V["drop_token"]["token_id"]] = {"name": "Kaj van het werk", "pair": contact["pairing_secret"],
                                                   "created": contact["issued"], "expires": contact["expires"], "key": None}
    return me


# --- encodings, hosts, keys ------------------------------------------------------

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


@pytest.mark.parametrize("host", V["hosts"]["valid"])
def test_valid_hosts(host):
    assert bv.is_host(host, allow_dev=False)


@pytest.mark.parametrize("host", V["hosts"]["must_reject"])
def test_invalid_hosts(host):
    assert not bv.is_host(host, allow_dev=False)


def test_localhost_only_in_development_mode():
    assert bv.is_host("localhost:8787", allow_dev=True) and bv.is_host("localhost", allow_dev=True)
    assert not bv.is_host("localhost:99999", allow_dev=True) and not bv.is_host("printer", allow_dev=True)


def test_refuses_to_connect_to_addresses_that_are_not_public(monkeypatch):
    def resolver(answer):
        return lambda host, port, **kw: [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answer]
    for private in (["127.0.0.1"], ["192.168.1.234"], ["10.0.0.5"], ["169.254.1.1"], ["100.64.0.1"], ["::1"], ["fd00::1"],
                    ["fe80::1"], ["::ffff:192.168.1.1"], ["0.0.0.0"], ["93.184.216.34", "192.168.1.1"]):
        monkeypatch.setattr(socket, "getaddrinfo", resolver(private))
        with pytest.raises(RuntimeError, match="not public"):
            bv._public_address("innocent.example", 443)
    monkeypatch.setattr(socket, "getaddrinfo", resolver(["93.184.216.34"]))
    assert bv._public_address("relay.example", 443) == "93.184.216.34"


# --- cards ---------------------------------------------------------------------------

def test_card_round_trip_and_signature():
    card = V["cards"]["valid"]
    me = ident(V["recipient"])
    uri = bv.make_card(me, bv.unb64(card["drop_token"]), bv.unb64(card["pairing_secret"]), expires=card["expires"])
    assert uri == card["uri"]
    parsed = bv.parse_card(card["uri"], now=V["cards"]["now"])
    assert parsed["address"] == V["recipient"]["address"] and parsed["name"] == card["name"]
    assert bv.b64(parsed["key"]) == card["encryption_key"] == V["recipient"]["encryption_public"]
    assert (parsed["token"], parsed["pair"], parsed["expires"]) == (card["drop_token"], card["pairing_secret"], card["expires"])


@pytest.mark.parametrize("name", list(V["cards"]["also_valid"]))
def test_other_valid_cards(name):
    case = V["cards"]["also_valid"][name]
    parsed = bv.parse_card(case["uri"], now=V["cards"]["now"])
    assert (parsed["expires"], parsed["name"]) == (case["expires"], case["name"])
    assert parsed["pair"] == V["cards"]["valid"]["pairing_secret"]


@pytest.mark.parametrize("name", list(V["cards"]["must_reject"]))
def test_bad_cards_are_refused(name):
    with pytest.raises(bv.Discard):
        bv.parse_card(V["cards"]["must_reject"][name], now=V["cards"]["now"])


# --- messages ------------------------------------------------------------------------

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
    card = bv.parse_card(V["cards"]["valid"]["uri"], now=V["cards"]["now"])
    sealed = bv.seal_message(ident(V["sender"]), card, message["ticket"], now=message["created"], message_id=bv.unb64(message["id"]))
    from nacl.public import PrivateKey, SealedBox
    padded = SealedBox(PrivateKey(bv.unb64(V["recipient"]["encryption_secret"]))).decrypt(sealed)
    assert padded[4:4 + int.from_bytes(padded[:4], "big")].decode() == m["signed_message_json"]


@pytest.mark.parametrize("name", [k for k in V["must_accept"] if k != "note"])
def test_must_accept(name):
    sealed = bv.unb64(V["must_accept"][name])
    _, message = bv.open_message(ident(V["recipient"]), sealed, now=NOW)
    assert message["type"] == "ticket"
    if name == "longer_than_one_block":
        assert len(sealed) > 48 + 4096 and (len(sealed) - 48) % 4096 == 0


@pytest.mark.parametrize("name", list(V["must_reject"]))
def test_must_reject(name):
    with pytest.raises(bv.Discard):
        bv.open_message(ident(V["recipient"]), bv.unb64(V["must_reject"][name]), now=NOW)


@pytest.mark.parametrize("name", [k for k in V["may_reject"] if k != "note"])
def test_may_reject_is_handled_without_crashing(name):
    try:
        bv.open_message(ident(V["recipient"]), bv.unb64(V["may_reject"][name]), now=NOW)
    except bv.Discard:
        pass  # this client rejects them, which is allowed


def test_someone_else_cannot_open_it():
    with pytest.raises(bv.Discard):
        bv.open_message(ident(V["sender"]), bv.unb64(V["message"]["sealed"]), now=NOW)


# --- pairing and contacts -------------------------------------------------------------

def test_contact_checks_in_order():
    me = recipient_with_contact()
    contact = next(iter(me["contacts"].values()))
    for step in V["contact_checks"]["steps"]:
        before = copy.deepcopy(me)
        try:
            outcome = "print" if bv.handle_message(me, bv.unb64(step["sealed"]), NOW) else "discard"
        except bv.Discard:
            outcome = "discard"
            assert me == before, f"a discarded message left a trace: {step['why']}"
        assert outcome == step["expect"], step["why"]
        assert contact["key"] == step["pinned_after"], step["why"]
    assert len(me["queue"]) == sum(s["expect"] == "print" for s in V["contact_checks"]["steps"])
    assert all(entry["contact"] == "Kaj van het werk" for entry in me["queue"])


def test_expired_card_cannot_pair():
    case = V["contact_checks"]["expired_card"]
    me = recipient_with_contact()
    with pytest.raises(bv.Discard, match="expired"):
        bv.handle_message(me, bv.unb64(case["sealed"]), case["now"])
    assert next(iter(me["contacts"].values()))["key"] is None


# --- tickets ----------------------------------------------------------------------------

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
    for case in V["tickets"]["text_cleaning"]:
        keep = case["where"] != "list item, caption, alt, names"
        assert bv.clean_text(case["input"], keep_line_feeds=keep) == case["output"], case
    dirty = V["tickets"]["text_cleaning"][0]["input"]
    rendered = bv.render_text({"blocks": [{"type": "text", "text": dirty}, {"type": "list", "items": [dirty]}]})
    assert all(ch == "\n" or (ch >= " " and not "\x7f" <= ch <= "\x9f") for ch in rendered), "no control characters survive"


def test_a_long_ticket_is_cut_off_by_the_recipient():
    ticket = {"blocks": [{"type": "list", "items": ["x"] * 50}] * 6}
    bv.validate_ticket(ticket)
    lines = bv.render_text(ticket, max_lines=40).split("\n")
    assert len(lines) == 41 and "cut off" in lines[-1]


# --- relay requests ---------------------------------------------------------------------

@pytest.mark.parametrize("index", range(len(V["owner_requests"])))
def test_owner_request_headers(index):
    r = V["owner_requests"][index]
    from nacl.signing import SigningKey
    expected_input = "\n".join(["bonvoyage-v1-request", r["method"], r["host"], r["path"], str(r["time"]),
                                __import__("hashlib").sha256(r["body"].encode()).hexdigest()])
    assert expected_input == r["signing_input"]
    sig = SigningKey(bv.unb64(r["signing_secret_seed"])).sign(r["signing_input"].encode()).signature
    assert f"t={r['time']},sig={bv.b64(sig)}" == r["header"]


def test_relay_response_handling(monkeypatch):
    case = V["relay_response"]
    me = ident(V["recipient"])
    deleted = []

    def fake(identity, method, path, body=None, **kw):
        if method == "GET":
            return 200, {"messages": [{"id": i, "received": 1, "token": "x", "body": "AAAA"} for i in case["ids_in_response"]]}, {}
        deleted.append(path.rsplit("/", 1)[1])
        return 204, None, {}
    monkeypatch.setattr(bv, "owner_request", fake)
    assert bv.receive(me) == []
    assert deleted == case["ids_to_process"]


def test_a_wrong_clock_stops_the_receive_loop(monkeypatch):
    me = ident(V["recipient"])
    calls = []

    def fake(identity, method, path, body=None, **kw):
        calls.append(method)
        return 200, {"messages": [{"id": "abc", "body": "AAAA"}]}, {"date": "Mon, 01 Jan 2001 00:00:00 GMT"}
    monkeypatch.setattr(bv, "owner_request", fake)
    with pytest.raises(RuntimeError, match="clock"):
        bv.receive(me)
    assert calls == ["GET"], "nothing is handled or deleted while the clock is wrong"


# --- end to end through a real relay ---------------------------------------------

@pytest.fixture
def relay(tmp_path, monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "PORT": str(port), "BONVOYAGE_DB": str(tmp_path / "relay.db"), "RELAY_HOST": f"localhost:{port}"}
    process = subprocess.Popen(["node", "src/server.js"], cwd=ROOT / "relay", env=env, stdout=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    monkeypatch.setenv("BONVOYAGE_DEV", "1")  # plain HTTP to localhost, for these tests only
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

    got = bv.receive(jan, persist=lambda: saves.append(copy.deepcopy(jan)))
    assert [c["name"] for c, _ in got] == ["Kaj van het werk"], "labelled with OUR name; the duplicate is discarded"
    assert len(saves) == 1 and saves[0]["seen"] and saves[0]["queue"], "recorded and queued on disk before being handed over"
    assert bv.render_text(got[0][1]["ticket"]) == "Welkom bij de club!\n[ ] koffie\n[ ] taart"
    contact = next(iter(jan["contacts"].values()))
    assert contact["key"] == bv.inbox_id(kaj)
    assert bv.receive(jan) == [], "handled messages were deleted from the relay"

    # Eve got hold of the card: the relay accepts her drop, Jan's pinned key does not. One alert, not one per message.
    for _ in range(3):
        bv.drop(card, bv.seal_message(eve, card, TICKET))
    assert bv.receive(jan) == [] and contact["alerted"] > 0

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
    bv.drop(card, bv.seal_message(kaj, card, TICKET))
    got = bv.receive(jan)
    assert len(got) == 1, "the good ticket arrives; every bad message was discarded and deleted"
    assert bv.receive(jan) == []


def test_a_failed_delete_loses_no_ticket(relay, monkeypatch):
    kaj, jan = bv.new_identity(relay, "Kaj"), bv.new_identity(relay, "Jan")
    bv.register(kaj)
    card = bv.parse_card(bv.issue_card(jan, "Kaj"))
    bv.register(jan)
    bv.drop(card, bv.seal_message(kaj, card, TICKET))
    real = bv.owner_request

    def flaky(identity, method, path, body=None, **kw):
        if method == "DELETE":
            raise RuntimeError("network went away")
        return real(identity, method, path, body, **kw)
    monkeypatch.setattr(bv, "owner_request", flaky)
    assert len(bv.receive(jan)) == 1 and len(jan["queue"]) == 1, "the ticket is in the queue although the delete failed"
    monkeypatch.setattr(bv, "owner_request", real)
    assert bv.receive(jan) == [] and len(jan["queue"]) == 1, "offered again by the relay, recognised as a repeat, and now deleted"
    assert bv.receive(jan) == []


def test_removed_and_paired_again_does_not_revive_old_messages(relay):
    kaj, jan = bv.new_identity(relay, "Kaj"), bv.new_identity(relay, "Jan")
    bv.register(kaj)
    now = int(time.time())
    old_card = bv.parse_card(bv.issue_card(jan, "Kaj", now=now - 5000))
    bv.register(jan)
    old = bv.seal_message(kaj, old_card, TICKET, now=now - 4000)
    jan["contacts"].clear()                      # Kaj is removed before that message is ever handled
    new_card = bv.parse_card(bv.issue_card(jan, "Kaj"))
    time.sleep(1.1)
    bv.register(jan)
    bv.drop(new_card, old)                        # a relay re-delivers the old message through the new token
    assert bv.receive(jan) == [], "a message created before the new card was issued is discarded"
    bv.drop(new_card, bv.seal_message(kaj, new_card, TICKET))
    assert len(bv.receive(jan)) == 1


def test_plain_http_needs_development_mode(monkeypatch):
    monkeypatch.delenv("BONVOYAGE_DEV", raising=False)
    assert not bv.is_host("localhost:8787")
    with pytest.raises(RuntimeError, match="not a relay host"):
        bv._http("GET", "localhost:8787", "/v1", None, {})
    with pytest.raises(ValueError):
        bv.new_identity("localhost:8787")
