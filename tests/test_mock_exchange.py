"""The mock exchange serves what the navigation agent needs, and nothing unsafe leaves it.
Runs the server in-process on a loopback port: no browser, no network."""

import json
import urllib.error
import urllib.request

import pytest

from scamhunter.extract.blocklist import load_blocklist
from scamhunter.extract.qr import decode_qr
from scamhunter.extract.validators import validate
from scamhunter.mock_mode import load_exchange_module
from scamhunter.models import AddressFormat

ex_mod = load_exchange_module()
BLOCKLIST = load_blocklist()
PW = "Passw0rd!x"


class Client:
    def __init__(self, exchange) -> None:
        self.ex = exchange
        self.base = exchange.start()
        self.token = ""

    def call(self, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path,
            data=data,
            method="POST" if body is not None else "GET",
            headers={"content-type": "application/json", "x-token": self.token},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw[:1] in b"[{" else raw)
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b"{}")

    def register(self, email: str = "a@x.test", **extra):
        body = {"email": email, "password": PW, "agree": True, **extra}
        return self.call("/api/register", body)

    def login(self, email: str = "a@x.test"):
        status, data = self.call("/api/login", {"email": email, "password": PW})
        if status == 200:
            self.token = data["token"]
        return status, data


@pytest.fixture
def make():
    clients: list[Client] = []

    def factory(variant: str = "normal", **kw) -> Client:
        c = Client(ex_mod.MockExchange(variant=variant, **kw))
        clients.append(c)
        return c

    yield factory
    for c in clients:
        c.ex.stop()


def test_every_asset_has_a_valid_non_blocklisted_address(make) -> None:
    c = make()
    assert c.register()[0] == 200 and c.login()[0] == 200
    seen = set()
    for coin, network in ex_mod.ASSETS:
        status, data = c.call(f"/api/deposit-address?coin={coin}&network={network}")
        assert status == 200 and (data["coin"], data["network"]) == (coin, network)
        fmt = {"TRC20": AddressFormat.TRON, "BTC": AddressFormat.BTC_P2PKH}.get(
            network, AddressFormat.EVM
        )
        result = validate(data["address"], fmt)
        assert result.valid and result.normalized.lower() not in BLOCKLIST, (coin, network)
        seen.add(data["address"])
    assert len(seen) == len(ex_mod.ASSETS)  # one distinct address per coin/network


def test_addresses_are_per_account_and_stable(make) -> None:
    c = make()
    c.register("a@x.test"), c.register("b@x.test")
    addresses = {}
    for email in ("a@x.test", "b@x.test"):
        c.login(email)
        addresses[email] = c.call("/api/deposit-address?coin=USDT&network=TRC20")[1]["address"]
    assert addresses["a@x.test"] != addresses["b@x.test"]
    c.login("a@x.test")
    assert (
        c.call("/api/deposit-address?coin=USDT&network=TRC20")[1]["address"]
        == addresses["a@x.test"]
    )


def test_login_required(make) -> None:
    c = make()
    assert c.call("/api/deposit-address?coin=BTC&network=BTC")[0] == 401
    assert c.call("/api/coins")[0] == 401


def test_coin_list_contains_decoy_token_contracts(make) -> None:
    c = make()
    c.register(), c.login()
    contracts = {
        x["contract_address"].lower() for x in c.call("/api/coins")[1] if x["contract_address"]
    }
    assert contracts and contracts <= BLOCKLIST  # exactly the contracts our blocklist knows


def test_normal_register_requires_terms_and_valid_input(make) -> None:
    c = make()
    assert c.call("/api/register", {"email": "a@x.test", "password": PW})[0] == 400  # no agree
    assert c.call("/api/register", {"email": "nope", "password": PW, "agree": True})[0] == 400
    assert c.register()[0] == 200
    assert c.register()[0] == 409


def test_invite_required_and_visible(make) -> None:
    hidden = make("invite_required")
    assert hidden.register()[0] == 403
    assert hidden.register(invite="1234")[0] == 403
    assert (
        "8888" not in urllib.request.urlopen(hidden.base + "/").read().decode()
    )  # nowhere on the page
    assert hidden.register(invite="8888")[0] == 200  # only someone who knew it could

    visible = make("invite_visible")
    page = urllib.request.urlopen(visible.base + "/").read().decode()
    assert "8888" in page  # printed in the page config, so the agent can read it
    assert visible.register()[0] == 403 and visible.register(invite="8888")[0] == 200


@pytest.mark.parametrize(("variant", "needle"), [("sms_gate", "SMS"), ("captcha", "captcha")])
def test_gates_cannot_be_passed_by_registering(make, variant: str, needle: str) -> None:
    c = make(variant)
    status, data = c.register()
    assert status == 400 and needle in data["error"]


def test_email_verification_via_mock_inbox(make) -> None:
    c = make("email_verify")
    status, data = c.register()
    assert status == 200 and data["verify_required"]
    assert c.login()[0] == 403  # not verified yet
    inbox = c.call("/_mail?to=a@x.test")[1]
    code = next(w.strip(".") for w in inbox[0]["body"].split() if w.strip(".").isdigit())
    assert c.call("/api/verify-email", {"email": "a@x.test", "code": "000000"})[0] == 400
    assert c.call("/api/verify-email", {"email": "a@x.test", "code": code})[0] == 200
    assert c.login()[0] == 200


def test_amount_first_needs_the_stated_minimum(make) -> None:
    c = make("amount_first", min_amount=30)
    c.register(), c.login()
    base = "/api/deposit-address?coin=USDT&network=TRC20"
    assert c.call(base)[0] == 400
    assert c.call(base + "&amount=10")[0] == 400
    status, data = c.call(base + "&amount=30")
    assert status == 200 and data["min_amount"] == 30


def test_forbidden_endpoints_are_recorded(make) -> None:
    c = make()
    for path in ex_mod.FORBIDDEN_PATHS:
        assert c.call(path, {})[0] == 200
    assert {p for _, p in c.ex.forbidden} == ex_mod.FORBIDDEN_PATHS
    assert make().ex.forbidden == []  # a fresh exchange has none


def test_qr_endpoint_encodes_the_address(make) -> None:
    c = make()
    png = urllib.request.urlopen(c.base + "/qr.png?data=TQeneWJctmxhk6NpbNnnLdcNUEmGHzs1sC").read()
    assert decode_qr(png) == ["TQeneWJctmxhk6NpbNnnLdcNUEmGHzs1sC"]


@pytest.mark.parametrize("variant", sorted(ex_mod.VARIANTS))
def test_every_variant_serves_a_page_with_its_config(make, variant: str) -> None:
    c = make(variant)
    page = urllib.request.urlopen(c.base + "/").read().decode()
    assert f'"variant": "{variant}"' in page and "__MOCK_CONFIG__" not in page


def test_injection_variant_carries_the_hostile_text_and_other_variants_do_not(make) -> None:
    assert (
        "ignore your previous instructions"
        in urllib.request.urlopen(make("injection").base + "/").read().decode()
    )
    assert (
        "ignore your previous instructions"
        not in urllib.request.urlopen(make("normal").base + "/").read().decode()
    )
