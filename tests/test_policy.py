"""Policy rules (DESIGN §5.5), tested on hand-built elements and page facts."""

import pytest

from scamhunter.agent.identity import new_identity
from scamhunter.agent.policy import LoopDetector, Policy, registrable
from scamhunter.browser.elements import Element
from scamhunter.browser.page_state import CaptchaWidget, PageFacts
from scamhunter.classify.domain import load_brands
from scamhunter.models import ActionType, AgentAction, BlockedReason

IDENTITY = new_identity("abc123@mail.test")
SITE = "bad-site.com"


def el(id: int, role: str, name: str, **kw) -> Element:
    box = kw.pop("box", (0, 0, 100, 30))
    return Element(id=id, role=role, name=name, box=box, in_view=True, clickable_only=False, **kw)


def facts(**kw) -> PageFacts:
    base = {
        "url": f"https://{SITE}/",
        "is_deposit_page": False,
        "stated_minimum": None,
        "has_card_or_bank_fields": False,
        "wallet_signature_request": False,
    }
    return PageFacts(**(base | kw))


def act(kind: ActionType, **kw) -> AgentAction:
    return AgentAction(type=kind, rationale="test", **kw)


def decide(action: AgentAction, elements=(), page=None, **policy_kw):
    policy = Policy(SITE, policy_kw.pop("identity", IDENTITY), **policy_kw)
    return policy.check(action, list(elements), page or facts())


def click(name: str, page=None, **policy_kw):
    return decide(act(ActionType.CLICK, element_id=1), [el(1, "button", name)], page, **policy_kw)


DEPOSIT = {"is_deposit_page": True}


# ---------- clicks ----------


@pytest.mark.parametrize(
    "name",
    [
        "I have paid",
        "I've paid",
        "I Have Paid ✓",
        "Payment done",
        "已支付",
        "Upload receipt",
        "Upload proof of payment",
        "Upload screenshot",
        "Confirm payment",
        "Pay now",
        "Buy",
        "Purchase",
        "Place order",
        "Checkout",
        "Withdraw",
        "Withdrawal",
        "提现",
        "Swap",
        "Sign",
        "Sign message",
        "Approve",
        "Authorize",
        "Sign in with Ethereum",
    ],
)
@pytest.mark.parametrize("page", [{}, DEPOSIT], ids=["any page", "deposit page"])
def test_always_blocked_clicks(name: str, page: dict) -> None:
    assert not click(name, facts(**page)).allowed


@pytest.mark.parametrize(
    "name",
    [
        "Register",
        "Sign up",
        "Sign in",
        "Log in",
        "Deposit",
        "USDT",
        "TRC20",
        "Assets",
        "Recharge",
        "Copy address",
        "Finance",
        "Transfer",
        "Next",
        "×",
    ],
)
def test_ordinary_clicks_are_allowed(name: str) -> None:
    assert click(name).allowed


@pytest.mark.parametrize("name", ["Confirm", "Next", "Recharge", "Submit order", "Continue"])
def test_deposit_submit_clicks_on_a_clean_deposit_page(name: str) -> None:
    assert click(name, facts(**DEPOSIT)).allowed


@pytest.mark.parametrize("name", ["Confirm", "Next", "Recharge", "Submit order"])
def test_deposit_submit_blocked_with_card_or_bank_fields(name: str) -> None:
    d = click(name, facts(**DEPOSIT, has_card_or_bank_fields=True))
    assert not d.allowed and d.blocked_at == BlockedReason.PAYMENT_REQUIRED
    assert click("USDT", facts(**DEPOSIT, has_card_or_bank_fields=True)).allowed


@pytest.mark.parametrize("page", [{}, DEPOSIT], ids=["any page", "deposit page"])
def test_deposit_submit_blocked_while_a_wallet_signature_is_requested(page: dict) -> None:
    assert not click("Confirm", facts(**page, wallet_signature_request=True)).allowed


def test_connect_wallet_needs_the_mock_wallet() -> None:
    blocked = click("Connect Wallet")
    assert not blocked.allowed and blocked.blocked_at == BlockedReason.WALLET_REQUIRED
    assert click("Connect Wallet", mock_wallet_active=True).allowed
    assert not click("Sign message", mock_wallet_active=True).allowed  # sign stays blocked


def test_click_unknown_or_disabled_element() -> None:
    assert not decide(act(ActionType.CLICK, element_id=9), [el(1, "button", "x")]).allowed
    assert not decide(
        act(ActionType.CLICK, element_id=1), [el(1, "button", "x", disabled=True)]
    ).allowed


def test_click_at_follows_the_element_under_the_point() -> None:
    elements = [el(1, "button", "I have paid", box=(100, 100, 80, 30))]
    on_trap = decide(act(ActionType.CLICK_AT, x=120, y=110), elements)
    assert not on_trap.allowed
    assert decide(act(ActionType.CLICK_AT, x=500, y=500), elements).allowed
    assert not decide(act(ActionType.CLICK_AT, x=-5, y=10), elements).allowed


def test_click_at_is_not_accepted_on_deposit_pages() -> None:
    assert not decide(act(ActionType.CLICK_AT, x=5, y=5), [], facts(**DEPOSIT)).allowed


# ---------- fill ----------


def fill(value: str, element: Element, page=None, **policy_kw):
    return decide(
        act(ActionType.FILL, element_id=element.id, value=value), [element], page, **policy_kw
    )


EMAIL = el(1, "textbox", "Email", input_type="email")
PASSWORD = el(1, "textbox", "Password", input_type="password")


def test_placeholders_resolve_only_to_known_identity_fields() -> None:
    assert fill("{identity.email}", EMAIL).allowed
    assert fill("{identity.password}", PASSWORD).allowed
    assert fill("{identity.first_name} {identity.last_name}", el(1, "textbox", "Name")).allowed
    assert not fill("{identity.ssn}", EMAIL).allowed
    assert not fill("{identity.email}", EMAIL, identity=None).allowed
    assert not fill("{other}", EMAIL).allowed


def test_password_rules() -> None:
    assert not fill("hunter2", PASSWORD).allowed  # only the placeholder, never a literal
    assert not fill("{identity.password}", el(1, "textbox", "Username")).allowed
    assert fill("{identity.password}", el(1, "textbox", "Confirm password")).allowed


@pytest.mark.parametrize(
    "value",
    [
        "real.person@gmail.com",
        "4111 1111 1111 1111",
        "12345678901234",
        "abandon ability able about above absent absorb abstract absurd accident account",
        "x" * 41,
    ],
)
def test_literals_that_look_like_personal_data_are_blocked(value: str) -> None:
    assert not fill(value, el(1, "textbox", "Invite code")).allowed


# ---------- the literal-value rule (2026-10-07: pilot site 145 typed an image CAPTCHA) ----------

INVITE = el(1, "textbox", "Invite code")


@pytest.mark.parametrize("value", ["ABC123", "888888", "USDT", "TRC20", "KG08", "hello"])
def test_a_literal_from_no_known_source_is_refused(value: str) -> None:
    d = fill(value, INVITE)
    assert not d.allowed and "not from a known source" in d.reason


def test_an_invitation_code_printed_on_the_page_may_be_typed() -> None:
    page = facts(printed_codes=("8888",))
    assert fill("8888", INVITE, page).allowed
    assert not fill("8889", INVITE, page).allowed  # never a guessed variant


def test_a_code_from_the_site_s_email_may_be_typed() -> None:
    policy = Policy(SITE, IDENTITY)
    code = el(1, "textbox", "Verification code")
    action = act(ActionType.FILL, element_id=1, value="482913")
    assert not policy.check(action, [code], facts()).allowed
    policy.add_code("482913")
    assert policy.check(action, [code], facts()).allowed


def test_placeholders_with_spaces_need_no_source() -> None:
    assert fill("{identity.first_name} {identity.last_name}", el(1, "textbox", "Name")).allowed


@pytest.mark.parametrize(
    "label",
    [
        "圖形驗證碼",
        "图形验证码",
        "图片验证码",
        "Enter the characters shown",
        "Captcha",
        "Image code",
    ],
)
def test_unambiguous_captcha_labels_are_captcha_fields(label: str) -> None:
    d = fill("KG08", el(1, "textbox", label))
    assert not d.allowed and d.blocked_at == BlockedReason.CAPTCHA


@pytest.mark.parametrize("label", ["請輸入驗證碼", "邮箱验证码", "Verification code"])
def test_a_plain_verification_code_label_is_not_a_captcha_by_itself(label: str) -> None:
    """Sites use the same words for email and SMS codes, so the label alone does not decide;
    an emailed code may still be typed there."""
    policy = Policy(SITE, IDENTITY)
    policy.add_code("53687")
    action = act(ActionType.FILL, element_id=1, value="53687")
    assert policy.check(action, [el(1, "textbox", label)], facts()).allowed


def test_a_field_inside_an_image_captcha_widget_is_never_filled() -> None:
    """The image-next-to-input rule: the widget box covers the input (pilot site 145)."""
    from scamhunter.browser.page_state import CaptchaWidget

    page = facts(captcha=(CaptchaWidget("image_text", (0, 0, 300, 40)),), captcha_challenge=True)
    field = el(1, "textbox", "請輸入驗證碼", box=(10, 5, 150, 30))
    policy = Policy(SITE, IDENTITY)
    policy.add_code("KG08")  # even a "known" value: a CAPTCHA field is never filled
    d = policy.check(act(ActionType.FILL, element_id=1, value="KG08"), [field], page)
    assert not d.allowed and d.blocked_at == BlockedReason.CAPTCHA


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        (el(1, "textbox", "Enter your seed phrase"), "secrets"),
        (el(1, "textbox", "Private key"), "secrets"),
        (el(1, "textbox", "Card number", hints="cc-number"), "card"),
        (el(1, "textbox", "CVV"), "card"),
        (el(1, "textbox", "IBAN"), "card"),
    ],
)
def test_secret_and_payment_fields_are_never_filled(field: Element, reason: str) -> None:
    d = fill("{identity.first_name}", field)
    assert not d.allowed and reason in d.reason


def test_identity_document_field_is_a_kyc_gate() -> None:
    d = fill("ABC", el(1, "textbox", "Passport number"))
    assert not d.allowed and d.blocked_at == BlockedReason.KYC


def test_fill_needs_a_text_field() -> None:
    assert not fill("x", el(1, "button", "Go")).allowed


# ---------- deposit amounts ----------

AMOUNT = el(1, "textbox", "Deposit amount")


def test_amount_is_the_stated_minimum() -> None:
    page = facts(**DEPOSIT, stated_minimum="30")
    assert fill("30", AMOUNT, page).allowed
    assert fill("30.0", AMOUNT, page).allowed
    d = fill("100", AMOUNT, page)
    assert not d.allowed and "30" in d.reason  # the model is told the number to type
    assert not fill("5000", AMOUNT, page).allowed
    assert not fill("{identity.first_name}", AMOUNT, page).allowed
    assert not fill("abc", AMOUNT, page).allowed


def test_amount_defaults_to_100_without_a_stated_minimum() -> None:
    assert fill("100", AMOUNT, facts(**DEPOSIT)).allowed
    assert not fill("101", AMOUNT, facts(**DEPOSIT)).allowed


def test_amount_field_only_on_a_deposit_page() -> None:
    assert not fill("100", AMOUNT, facts()).allowed


# ---------- select, press, wait, scroll, goto ----------


def test_select_must_name_a_listed_option() -> None:
    dropdown = el(1, "combobox", "Network", options=("TRC20", "ERC20"))
    assert decide(act(ActionType.SELECT, element_id=1, value="trc20"), [dropdown]).allowed
    assert not decide(act(ActionType.SELECT, element_id=1, value="BEP20"), [dropdown]).allowed
    assert not decide(
        act(ActionType.SELECT, element_id=1, value="x"), [el(1, "button", "x")]
    ).allowed


def test_press_scroll_wait_limits() -> None:
    assert decide(act(ActionType.PRESS, value="Enter")).allowed
    assert not decide(act(ActionType.PRESS, value="F12")).allowed
    assert not decide(act(ActionType.PRESS, value="Control+A")).allowed
    assert decide(act(ActionType.SCROLL, value="down")).allowed
    assert not decide(act(ActionType.SCROLL, value="sideways")).allowed
    assert decide(act(ActionType.WAIT, value="5")).allowed
    assert not decide(act(ActionType.WAIT, value="6")).allowed
    assert not decide(act(ActionType.WAIT, value="soon")).allowed


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        (f"https://{SITE}/deposit", True),
        (f"https://h5.{SITE}/x?y=1", True),
        ("https://other.example/", False),
        (f"https://{SITE}.evil.example/", False),
        (f"https://evil.example/{SITE}", False),
        (f"https://user:pw@{SITE}/", False),
        ("javascript:alert(1)", False),
        ("file:///etc/passwd", False),
        ("/relative", False),
        ("data:text/html,x", False),
    ],
)
def test_goto_stays_on_the_site(url: str, allowed: bool) -> None:
    assert decide(act(ActionType.GOTO, url=url)).allowed is allowed


def test_goto_in_mock_mode_uses_the_loopback_host_as_the_site() -> None:
    policy = Policy("127.0.0.1")
    assert policy.check(act(ActionType.GOTO, url="http://127.0.0.1:8123/x"), [], facts()).allowed
    assert not policy.check(act(ActionType.GOTO, url="http://localhost:8123/"), [], facts()).allowed


def test_registrable_domains() -> None:
    assert registrable("h5.bit-main.cc") == "bit-main.cc"
    assert registrable("127.0.0.1") == "127.0.0.1"
    assert registrable("A.B.Example.CO.UK") == "example.co.uk"


def test_check_email_needs_a_mailbox() -> None:
    assert decide(act(ActionType.CHECK_EMAIL)).allowed
    assert not decide(act(ActionType.CHECK_EMAIL), identity=None).allowed
    assert decide(act(ActionType.BACK)).allowed and decide(act(ActionType.DONE)).allowed


# ---------- loop detection ----------


def test_same_url_and_action_three_times_in_a_row_is_no_progress() -> None:
    loop = LoopDetector()
    same = act(ActionType.CLICK, element_id=4)
    assert [loop.record("https://a/", same) for _ in range(3)] == [False, False, True]
    assert not loop.record("https://a/", act(ActionType.CLICK, element_id=5))  # different: resets
    assert not loop.record("https://b/", act(ActionType.CLICK, element_id=5))  # other URL


# ---------- identity documents, uploads, links (DESIGN §5.5, 2026-10-06) ----------


@pytest.mark.parametrize(
    "field",
    [
        el(1, "textbox", "Upload ID card", input_type="file"),
        el(1, "textbox", "Passport photo", input_type="file"),
        el(1, "textbox", "", input_type="file", hints="id_card_front"),
    ],
)
def test_identity_document_upload_field_is_a_kyc_gate(field: Element) -> None:
    for kind, kw in ((ActionType.CLICK, {}), (ActionType.FILL, {"value": "x"})):
        d = decide(act(kind, element_id=1, **kw), [field])
        assert not d.allowed and d.blocked_at == BlockedReason.KYC


@pytest.mark.parametrize("name", ["Upload ID", "Upload your passport", "Take a selfie"])
def test_identity_document_upload_buttons_are_a_kyc_gate(name: str) -> None:
    d = click(name)
    assert not d.allowed and d.blocked_at == BlockedReason.KYC


def test_other_file_inputs_are_never_used() -> None:
    d = decide(act(ActionType.CLICK, element_id=1), [el(1, "textbox", "Avatar", input_type="file")])
    assert not d.allowed and d.blocked_at is None


@pytest.mark.parametrize(
    ("href", "allowed"),
    [
        (f"https://{SITE}/register", True),
        (f"https://www.{SITE}/login", True),
        ("javascript:void(0)", True),
        ("#/deposit", True),
        ("https://evil.test/claim-bonus", False),
        ("https://t.me/support_bot", False),
        (f"https://{SITE}.evil.test/", False),
    ],
)
def test_links_stay_on_the_site(href: str, allowed: bool) -> None:
    d = decide(act(ActionType.CLICK, element_id=1), [el(1, "link", "Claim bonus", href=href)])
    assert d.allowed is allowed


# ---------- CAPTCHA: one checkbox click, never a challenge (DESIGN §7, 2026-10-06) ----------

RECAPTCHA = CaptchaWidget("recaptcha_checkbox", (10, 200, 300, 80))
CHALLENGE = CaptchaWidget("challenge", (10, 300, 300, 400))


def test_one_click_on_a_checkbox_captcha_then_a_gate() -> None:
    policy = Policy(SITE, IDENTITY)
    page = facts(captcha=(RECAPTCHA,))
    at = act(ActionType.CLICK_AT, x=40, y=240)
    assert policy.check(at, [], page).allowed
    again = policy.check(at, [], page)
    assert not again.allowed and again.blocked_at == BlockedReason.CAPTCHA
    assert "done with blocked_at captcha" in again.reason


def test_an_element_inside_the_widget_counts_as_the_widget() -> None:
    policy = Policy(SITE, IDENTITY)
    page = facts(captcha=(RECAPTCHA,))
    box = el(3, "clickable", "☐", box=(20, 220, 20, 20))
    assert policy.check(act(ActionType.CLICK, element_id=3), [box], page).allowed
    second = policy.check(act(ActionType.CLICK, element_id=3), [box], page)
    assert second.blocked_at == BlockedReason.CAPTCHA


def test_a_challenge_is_never_touched() -> None:
    policy = Policy(SITE, IDENTITY)
    page = facts(captcha=(RECAPTCHA, CHALLENGE), captcha_challenge=True)
    for x, y in ((40, 240), (100, 500)):  # the checkbox and the image grid
        d = policy.check(act(ActionType.CLICK_AT, x=x, y=y), [], page)
        assert not d.allowed and d.blocked_at == BlockedReason.CAPTCHA
    assert policy.captcha_clicks == 0


@pytest.mark.parametrize("kind", ["hcaptcha", "slider"])
def test_other_captcha_kinds_are_gates(kind: str) -> None:
    page = facts(captcha=(CaptchaWidget(kind, (10, 200, 300, 80)),))
    d = decide(act(ActionType.CLICK_AT, x=40, y=240), page=page)
    assert not d.allowed and d.blocked_at == BlockedReason.CAPTCHA


def test_captcha_by_label_when_the_widget_is_not_detected() -> None:
    policy = Policy(SITE, IDENTITY)
    robot = el(1, "clickable", "I'm not a robot")
    assert policy.check(act(ActionType.CLICK, element_id=1), [robot], facts()).allowed
    d = policy.check(act(ActionType.CLICK, element_id=1), [robot], facts())
    assert d.blocked_at == BlockedReason.CAPTCHA


def test_captcha_fields_are_never_filled() -> None:
    field = el(1, "textbox", "Enter the captcha")
    d = decide(act(ActionType.FILL, element_id=1, value="abcd"), [field])
    assert not d.allowed and d.blocked_at == BlockedReason.CAPTCHA


def test_clicks_outside_the_widget_are_unaffected() -> None:
    page = facts(captcha=(RECAPTCHA,))
    assert decide(act(ActionType.CLICK, element_id=1), [el(1, "button", "Register")], page).allowed


# ---------- the one cross-domain hop (DESIGN §5.5, 2026-10-07) ----------


def link(name: str, href: str, policy: Policy | None = None):
    policy = policy or Policy(SITE, IDENTITY, brands=load_brands())
    action = act(ActionType.CLICK, element_id=1)
    return policy.check(action, [el(1, "link", name, href=href)], facts())


@pytest.mark.parametrize(
    "text",
    ["Login", "Log in", "Sign up", "Register now", "App", "Trade", "Start trading", "登录", "注册"],
)
def test_a_login_style_link_to_another_domain_is_a_hop_to_confirm(text: str) -> None:
    d = link(text, "https://app.neurochain.uk/login")
    assert d.allowed and d.hop_url == "https://app.neurochain.uk/login" and d.hop_text == text


@pytest.mark.parametrize(
    ("text", "href", "why"),
    [
        ("Login", "https://t.me/support", "social"),
        ("Join us on WhatsApp", "https://wa.me/123", "social"),
        ("Login", "https://www.facebook.com/x", "social"),
        ("App", "https://apps.apple.com/app/x", "social"),
        ("App", "https://play.google.com/store/apps/x", "social"),
        ("Login", "https://www.binance.com/en/login", "the real Binance"),
        ("Support", "https://other-domain.example/help", "only Login"),
        ("Download App", "https://other-domain.example/x.apk", "only Login"),
        ("Docs", "https://other-domain.example/docs", "only Login"),
    ],
)
def test_other_cross_domain_links_are_refused_and_recorded(text: str, href: str, why: str) -> None:
    d = link(text, href)
    assert not d.allowed and d.hop_url is None
    assert d.linked_url == href, "refused links still go to linked_domains"
    assert why.lower() in d.reason.lower()


def test_after_the_hop_the_agent_is_locked_to_the_new_domain_and_cannot_hop_again() -> None:
    policy = Policy(SITE, IDENTITY, brands=load_brands())
    assert link("Login", "https://app.neurochain.uk/", policy).hop_url
    policy.lock_to("neurochain.uk")
    assert policy.site_domain == "neurochain.uk"
    again = link("Trade", "https://third-domain.example/", policy)
    assert not again.allowed and "already used" in again.reason
    back = link("Home", "https://" + SITE + "/", policy)  # the old domain is now off-site too
    assert not back.allowed
    policy.unlock()
    assert policy.site_domain == SITE and link("Login", "https://x-app.example/", policy).hop_url


def test_goto_never_hops() -> None:
    d = decide(act(ActionType.GOTO, url="https://app.neurochain.uk/login"))
    assert not d.allowed and d.hop_url is None
