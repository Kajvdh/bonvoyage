"""Checks the reference client against the test vectors and against a real relay.

    uv run --with pynacl --with pytest pytest examples/

The end-to-end tests start the Node relay from ../relay on a free port.
"""
import copy
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import threading
import time

import pytest

import bonvoyage as bv

ROOT = pathlib.Path(__file__).parent.parent
V = json.loads((ROOT / "vectors" / "v1.json").read_text(encoding="utf-8"))
NOW = V["now"]


def ident(who: dict) -> dict:
    return {"relay": who["address"].split("@")[1], "name": who["name"], "sign": who["signing_secret_seed"],
            "enc": who["encryption_secret"], "contacts": {}, "cards": {}, "seen": {}, "queue": []}


def recipient_with_contact() -> dict:
    """The recipient as it is after issuing `cards.valid` to someone it calls "Kaj van het werk"."""
    me = ident(V["recipient"])
    contact = V["contact_checks"]["contact"]
    me["contacts"][V["drop_token"]["token_id"]] = {"name": "Kaj van het werk", "pair": contact["pairing_secret"], "created": contact["issued"],
                                                   "expires": contact["expires"], "state": "open", "key": None}
    return me


def outcome_of(me: dict, sealed: str, now: int, **kw) -> str:
    try:
        entry = bv.handle_message(me, bv.unb64(sealed), now, **kw)
    except bv.Discard:
        return "discard"
    if entry is None:
        return "discard"
    return "hold" if entry["held"] else "print"


# --- encodings, hosts, addresses, keys --------------------------------------------

def test_keys_addresses_tokens_and_fingerprints():
    for who in (V["sender"], V["recipient"], V["stranger"]):
        me = ident(who)
        assert bv.inbox_id(me) == who["inbox_id"] == who["signing_public"]
        assert bv.address(me) == who["address"]
        assert bv.fingerprint(bv.unb64(who["signing_public"], 32)) == who["fingerprint"]
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


@pytest.mark.parametrize("address", V["addresses"]["public"])
def test_public_addresses(address):
    assert bv.is_public_address(address)


@pytest.mark.parametrize("address", V["addresses"]["must_refuse"])
def test_addresses_a_client_must_not_connect_to(address):
    assert not bv.is_public_address(address)


def test_every_resolved_address_must_be_public(monkeypatch):
    def resolver(answer):
        return lambda host, port, **kw: [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answer]
    monkeypatch.setattr(socket, "getaddrinfo", resolver(["93.184.216.34", "192.168.1.1"]))
    with pytest.raises(RuntimeError, match="not public"):
        bv._public_address("innocent.example", 443)
    monkeypatch.setattr(socket, "getaddrinfo", resolver(["93.184.216.34"]))
    assert bv._public_address("relay.example", 443) == "93.184.216.34"


def test_proof_of_work():
    case = V["proof_of_work"]
    assert bv.proof_of_work(case["inbox_id"], case["bits"]) == case["nonce"]
    digest = hashlib.sha256(case["input"].encode()).digest()
    assert digest.hex() == case["digest_hex"] and bv.leading_zero_bits(digest) >= case["bits"]
    assert bv.leading_zero_bits(bytes([0, 0, 0x1f])) == 19 and bv.leading_zero_bits(bytes(32)) == 256


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


def test_a_card_is_checked_once_and_then_kept():
    """Taking a card in on day 6 and sending on day 8 must work: the expiry is not looked at again."""
    card = V["cards"]["valid"]
    stored = bv.parse_card(card["uri"], now=card["expires"] - 86400)
    sealed = bv.seal_message(ident(V["sender"]), {**stored, "key": bv.b64(stored["key"])}, {"blocks": []}, now=card["expires"] + 86400)
    assert len(sealed) == 48 + 4096
    with pytest.raises(bv.Discard, match="expired"):
        bv.parse_card(card["uri"], now=card["expires"] + 1)


def test_a_replacement_card_cannot_pair_anyone():
    me = recipient_with_contact()
    old = next(iter(me["contacts"]))
    with pytest.raises(ValueError):
        bv.replace_token(me, old)
    me = recipient_with_contact()
    me["contacts"][old].update(state="paired", key=V["sender"]["signing_public"])
    card = bv.parse_card(bv.replace_token(me, old))
    assert old not in me["contacts"] and len(me["contacts"]) == 1
    contact = next(iter(me["contacts"].values()))
    assert contact["key"] == V["sender"]["signing_public"] and card["pair"] != contact["pair"]
    assert all(c["pair"] != card["pair"] for c in me["contacts"].values()), "the secret on the new card is stored nowhere"


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


def test_deep_nesting_is_refused_before_parsing():
    with pytest.raises(bv.Discard, match="nested"):
        bv.parse_json(b"[" * 100000 + b"]" * 100000)
    assert bv.parse_json(b'{"a":"[[[[[[[[[[[[[[[[[[[[ \\" [[[["}') == {"a": '[[[[[[[[[[[[[[[[[[[[ " [[[['}, "brackets inside strings do not count"


# --- pairing and contacts -------------------------------------------------------------

def test_contact_checks_in_order():
    me = recipient_with_contact()
    contact = next(iter(me["contacts"].values()))
    for step in V["contact_checks"]["steps"]:
        if step.get("action") == "confirm":
            assert bv.confirm(me, contact["name"]) == 2
        else:
            before = (copy.deepcopy(me["contacts"]), copy.deepcopy(me["queue"]))
            queued = len(me["queue"])
            outcome = outcome_of(me, step["sealed"], NOW)
            assert outcome == step["expect"], step["why"]
            if outcome == "discard":
                assert (me["contacts"], me["queue"]) == before, f"a discarded message changed a contact or the queue: {step['why']}"
            else:
                assert len(me["queue"]) == queued + 1
            if "notice_fingerprint" in step:
                assert step["notice_fingerprint"] in me["queue"][-1]["notice"]
                assert "Kaj van het werk" in me["queue"][-1]["notice"]
        assert (contact["state"], contact["key"]) == (step["state_after"], step["pinned_after"]), step["why"]
    assert not any(q["held"] for q in me["queue"]) and len(me["queue"]) == 4
    assert all(entry["contact"] == "Kaj van het werk" for entry in me["queue"])


def test_a_candidate_that_does_not_pair_is_not_recorded():
    me = recipient_with_contact()
    steps = V["contact_checks"]["steps"]
    for step in steps[:3]:
        assert outcome_of(me, step["sealed"], NOW) == "discard"
    assert me["seen"] == {}, "nothing about a candidate is remembered"


def test_held_tickets_are_limited():
    case = V["contact_checks"]["held_limit"]
    me = recipient_with_contact()
    assert [outcome_of(me, sealed, NOW) for sealed in case["sealed"]] == case["expect"]
    assert sum(q["held"] for q in me["queue"]) == 5 and len(me["seen"]) == 7, "the two that were dropped are still recorded as handled"


def test_declining_removes_the_contact_and_its_held_tickets():
    me = recipient_with_contact()
    assert outcome_of(me, V["message"]["sealed"], NOW) == "hold"
    bv.remove_contact(me, "Kaj van het werk")
    assert me["contacts"] == {} and me["queue"] == []


def test_expired_card_cannot_pair():
    case = V["contact_checks"]["expired_card"]
    me = recipient_with_contact()
    with pytest.raises(bv.Discard, match="expired"):
        bv.handle_message(me, bv.unb64(case["sealed"]), case["now"])
    contact = next(iter(me["contacts"].values()))
    assert (contact["state"], contact["key"]) == (case["state_after"], case["pinned_after"])


def test_two_contacts():
    case = V["contact_checks"]["two_contacts"]
    me = recipient_with_contact()
    first = next(iter(me["contacts"].values()))
    first["name"] = "first"
    second = {**first, "name": "second", "pair": case["second_pairing_secret"]}
    me["contacts"]["second-token"] = second
    for step in case["steps"]:
        queued = len(me["queue"])
        assert outcome_of(me, step["sealed"], NOW, auto_confirm=True) == step["expect"], step["why"]
        if step["contact"]:
            assert me["queue"][-1]["contact"] == step["contact"], step["why"]
        else:
            assert len(me["queue"]) == queued
        assert {"first": first["key"], "second": second["key"]} == step["pinned"], step["why"]


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
                                hashlib.sha256(r["body"].encode()).hexdigest()])
    assert expected_input == r["signing_input"]
    sig = SigningKey(bv.unb64(r["signing_secret_seed"])).sign(r["signing_input"].encode()).signature
    assert f"t={r['time']},sig={bv.b64(sig)}" == r["header"]


def date_now() -> dict:
    return {"date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())}


def test_relay_response_handling(monkeypatch):
    case = V["relay_response"]
    me = ident(V["recipient"])
    deleted = []

    def fake(identity, method, path, body=None, **kw):
        if method == "GET":
            return 200, {"messages": [{"id": i, "received": 1, "token": "x", "body": "AAAA"} for i in case["ids_in_response"]]}, date_now()
        deleted.append(path.rsplit("/", 1)[1])
        return 204, None, {}
    monkeypatch.setattr(bv, "owner_request", fake)
    assert bv.receive(me) == []
    assert deleted == case["ids_to_process"]


@pytest.mark.parametrize("headers", [{"date": "Mon, 01 Jan 2001 00:00:00 GMT"}, {}, {"date": "soon"}])
def test_a_wrong_or_unknown_clock_stops_the_receive_loop(monkeypatch, headers):
    me = ident(V["recipient"])
    calls = []

    def fake(identity, method, path, body=None, **kw):
        calls.append(method)
        return 200, {"messages": [{"id": "abc", "body": "AAAA"}]}, headers
    monkeypatch.setattr(bv, "owner_request", fake)
    with pytest.raises(RuntimeError, match="clock"):
        bv.receive(me)
    assert calls == ["GET"], "nothing is handled or deleted while the clock cannot be trusted"


def test_a_slow_relay_cannot_hold_a_request_beyond_the_deadline(monkeypatch):
    """A relay that sends one byte now and then must not keep a request open for as long as it likes."""
    monkeypatch.setenv("BONVOYAGE_DEV", "1")
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def trickle():
        connection, _ = server.accept()
        connection.recv(65536)
        try:
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            for _ in range(100):
                connection.sendall(b"x")
                time.sleep(0.2)
        except OSError:
            pass
        connection.close()
    threading.Thread(target=trickle, daemon=True).start()
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="too long"):
        bv._http("GET", f"localhost:{port}", "/v1", None, {}, deadline=1.0)
    assert time.monotonic() - started < 3, "the deadline is for the whole request, not per read"
    server.close()


# --- end to end through a real relay ---------------------------------------------

@pytest.fixture
def relay(tmp_path, monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "PORT": str(port), "BONVOYAGE_DB": str(tmp_path / "relay.db"), "RELAY_HOST": f"localhost:{port}", "POW_BITS": "8"}
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
        assert who["pow"]["bits"] == 8, "the relay asked for proof of work and the client did it"

    card = bv.parse_card(bv.issue_card(jan, "Kaj van het werk"))
    bv.register(jan)
    saves = []
    sealed = bv.seal_message(kaj, card, TICKET)
    bv.drop(card, sealed)
    bv.drop(card, sealed)  # the relay delivers the same message twice

    got = bv.receive(jan, persist=lambda: saves.append(copy.deepcopy(jan)))
    assert [(e["contact"], e["held"]) for e in got] == [("Kaj van het werk", True)], "labelled with OUR name; held until confirmed; duplicate discarded"
    assert len(saves) == 1 and saves[0]["seen"] and saves[0]["queue"], "recorded and queued on disk before being handed over"
    assert bv.fingerprint(bv.unb64(bv.inbox_id(kaj), 32)) in got[0]["notice"], "the owner is shown the sender's fingerprint"
    contact = next(iter(jan["contacts"].values()))
    assert (contact["state"], contact["key"]) == ("pending", bv.inbox_id(kaj))
    assert bv.receive(jan) == [], "handled messages were deleted from the relay"

    # Eve got hold of the card: the relay accepts her drop, Jan's pinned key does not. One alert, not one per message.
    for _ in range(3):
        bv.drop(card, bv.seal_message(eve, card, TICKET))
    assert bv.receive(jan) == [] and contact["alerted"] > 0

    assert bv.confirm(jan, "Kaj van het werk") == 1 and contact["state"] == "paired"
    assert bv.render_text(jan["queue"][0]["message"]["ticket"]) == "Welkom bij de club!\n[ ] koffie\n[ ] taart"
    bv.drop(card, bv.seal_message(kaj, card, TICKET))
    assert [e["held"] for e in bv.receive(jan)] == [False], "after confirmation tickets are no longer held"

    # Jan removes the contact: the relay now refuses the card.
    bv.remove_contact(jan, "Kaj van het werk")
    time.sleep(1.1)
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
    got = bv.receive(jan, auto_confirm=True)
    assert len(got) == 1 and not got[0]["held"], "the good ticket arrives; every bad message was discarded and deleted"
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
    assert len(bv.receive(jan, auto_confirm=True)) == 1 and len(jan["queue"]) == 1, "the ticket is in the queue although the delete failed"
    monkeypatch.setattr(bv, "owner_request", real)
    assert bv.receive(jan) == [] and len(jan["queue"]) == 1, "offered again by the relay, recognised as a repeat, and now deleted"
    assert bv.receive(jan) == []


def test_a_full_disk_does_not_cost_a_ticket(relay):
    kaj, jan = bv.new_identity(relay, "Kaj"), bv.new_identity(relay, "Jan")
    bv.register(kaj)
    card = bv.parse_card(bv.issue_card(jan, "Kaj"))
    bv.register(jan)
    bv.drop(card, bv.seal_message(kaj, card, TICKET))
    on_disk = copy.deepcopy(jan)

    def full_disk():
        raise OSError(28, "No space left on device")
    with pytest.raises(bv.LocalFailure):
        bv.receive(jan, persist=full_disk, auto_confirm=True)
    # After a restart the client has what was on disk, and the message is still at the relay.
    got = bv.receive(on_disk, auto_confirm=True)
    assert len(got) == 1, "our own failure did not delete the message"


def test_a_removed_inbox_is_created_again(relay):
    jan = bv.new_identity(relay, "Jan")
    bv.register(jan)
    bv.issue_card(jan, "Kaj")
    bv.register(jan)
    time.sleep(1.1)
    assert bv.owner_request(jan, "DELETE", f"/v1/inbox/{bv.inbox_id(jan)}")[0] == 204  # stands in for the relay removing it
    time.sleep(1.1)
    assert bv.receive(jan) == [], "a 404 on collect is not an error"
    status, answer, _ = bv.owner_request(jan, "GET", f"/v1/inbox/{bv.inbox_id(jan)}/messages")
    assert status == 200 and answer == {"messages": []}, "the inbox exists again, with the same tokens"


def test_old_messages_do_not_come_back_after_pairing_again(relay):
    """The 600-second rule: Kaj stays the same key, the contact is new, the old message predates it."""
    kaj, jan = bv.new_identity(relay, "Kaj"), bv.new_identity(relay, "Jan")
    bv.register(kaj)
    now = int(time.time())
    first_card = bv.parse_card(bv.issue_card(jan, "Kaj", now=now - 5000))
    old = bv.seal_message(kaj, first_card, TICKET, now=now - 4000)       # made, but never handled
    bv.remove_contact(jan, "Kaj")
    new_card = bv.parse_card(bv.issue_card(jan, "Kaj"))
    bv.register(jan)
    bv.drop(new_card, bv.seal_message(kaj, new_card, TICKET))
    assert len(bv.receive(jan, auto_confirm=True)) == 1                   # Kaj is paired again, pinned
    assert next(iter(jan["contacts"].values()))["key"] == bv.inbox_id(kaj)
    bv.drop(new_card, old)                                                # a relay re-delivers the old one
    with pytest.raises(bv.Discard, match="older than this contact"):
        bv.handle_message(copy.deepcopy(jan), old, now)
    assert bv.receive(jan) == [], "a message created before the new card was issued is discarded"


def test_plain_http_needs_development_mode(monkeypatch):
    monkeypatch.delenv("BONVOYAGE_DEV", raising=False)
    assert not bv.is_host("localhost:8787")
    with pytest.raises(RuntimeError, match="not a relay host"):
        bv._http("GET", "localhost:8787", "/v1", None, {})
    with pytest.raises(ValueError):
        bv.new_identity("localhost:8787")


def test_a_card_wrapped_in_a_web_link_is_accepted():
    card = V["cards"]["valid"]
    plain = bv.parse_card(card["uri"], now=V["cards"]["now"])
    for wrapped in ("https://bonvoyage.example/card/#" + card["uri"],
                    "  https://bonvoyage.example/card/#" + card["uri"].replace("://", "%3A%2F%2F") + "\n"):
        assert bv.parse_card(wrapped, now=V["cards"]["now"]) == plain
    with pytest.raises(bv.Discard):
        bv.parse_card("https://bonvoyage.example/card/#nothing-here", now=V["cards"]["now"])
    with pytest.raises(bv.Discard):
        bv.parse_card("https://bonvoyage.example/card/", now=V["cards"]["now"])
