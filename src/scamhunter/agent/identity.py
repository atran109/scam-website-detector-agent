"""Synthetic identity, placeholder resolution, and the disposable mailbox (DESIGN §5.5).

The model never sees or invents personal data: it writes placeholders such as
`{identity.email}` and the code substitutes the synthetic values when the action runs.
Mail is untrusted input like any page: it is only ever shown to the model inside a data block."""

import re
import secrets
import string
from dataclasses import dataclass, field
from random import Random

import httpx

from scamhunter.llm.sanitize import untrusted
from scamhunter.models import Identity

FIRST_NAMES = ["Alex", "Jamie", "Morgan", "Taylor", "Jordan", "Casey", "Riley", "Quinn", "Avery"]
LAST_NAMES = ["Walker", "Bennett", "Hayes", "Foster", "Ellis", "Brooks", "Reed", "Sutton", "Lane"]
PLACEHOLDER = re.compile(r"\{identity\.([a-z_]+)\}")
FIELDS = ("email", "password", "username", "first_name", "last_name", "phone")


def new_identity(email: str, rng: Random | None = None) -> Identity:
    """A throwaway identity around a disposable mailbox address. Names are common words, not a
    real person; the phone number is in the range reserved for fiction (212-555-0100..0199)."""
    rng = rng or Random(secrets.randbits(64))
    first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
    password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    return Identity(
        identity_id=f"id-{secrets.token_hex(4)}",
        first_name=first,
        last_name=last,
        email=email,
        password=f"Aa1!{password}",  # satisfies the usual upper/lower/digit/symbol rules
        phone=f"+1212555{rng.randint(100, 199):04d}",
        username=f"{first}{last}{rng.randint(1000, 9999)}".lower(),
    )


def placeholders_in(value: str) -> list[str]:
    return PLACEHOLDER.findall(value)


def resolve_placeholders(value: str, identity: Identity) -> str:
    """Substitute `{identity.<field>}`. Unknown or empty fields raise ValueError (the policy has
    already rejected them, so this is a second check)."""

    def sub(match: re.Match[str]) -> str:
        name = match.group(1)
        field_value = getattr(identity, name, None) if name in FIELDS else None
        if not field_value:
            raise ValueError(f"unknown identity field: {name}")
        return str(field_value)

    return PLACEHOLDER.sub(sub, value)


# ---------- verification mail ----------


@dataclass(frozen=True)
class Verification:
    code: str | None
    links: list[str] = field(default_factory=list)


_CODE_NEAR_WORD = re.compile(
    r"(?:code|otp|pin|verification|verify)\D{0,40}?\b(\d{4,8})\b", re.I | re.S
)
_URL = re.compile(r"https?://[^\s<>\"')]+")


def extract_verification(text: str) -> Verification:
    """A numeric code near a word like "code"/"verification", and any links. Both are returned
    as found; the policy decides whether a link may be opened (same registrable domain only)."""
    code = _CODE_NEAR_WORD.search(text)
    links = list(dict.fromkeys(_URL.findall(text)))[:5]
    return Verification(code.group(1) if code else None, links)


def describe_message(subject: str, body: str) -> str:
    """What `check_email` returns to the model: the message as an inert data block, plus what
    the code found in it."""
    found = extract_verification(f"{subject}\n{body}")
    lines = [untrusted("email", f"Subject: {subject}\n\n{body}", 1500)]
    if found.code:
        lines.append(f"Code found: {found.code}")
    if found.links:
        lines.append("Links found: " + " ".join(found.links))
    return "\n".join(lines)


@dataclass(frozen=True)
class MailMessage:
    subject: str
    body: str


class MailTmMailbox:
    """mail.tm disposable mailbox (decided 2026-10-05). The API token lives only in this object's
    memory: never logged, never written to disk, and hidden from repr. Pass an `httpx.AsyncClient`
    that goes through the egress proxy.

    NOT yet exercised against the live API (the sandbox has no route to it); the request and
    response shapes follow mail.tm's public documentation and are covered by a mocked transport.
    The first real use is the pilot."""

    def __init__(self, client: httpx.AsyncClient, base_url: str = "https://api.mail.tm") -> None:
        self._client = client
        self._base = base_url
        self._token: str | None = None
        self.address: str | None = None
        self._seen: set[str] = set()

    def __repr__(self) -> str:
        return f"MailTmMailbox(address={self.address!r})"

    async def create(self) -> str:
        """Open a mailbox and return its address."""
        domains = (await self._client.get(f"{self._base}/domains")).json()["hydra:member"]
        if not domains:
            raise RuntimeError("mail.tm offers no domains")
        address = f"{secrets.token_hex(6)}@{domains[0]['domain']}"
        password = secrets.token_urlsafe(16)
        created = await self._client.post(
            f"{self._base}/accounts", json={"address": address, "password": password}
        )
        created.raise_for_status()
        token = await self._client.post(
            f"{self._base}/token", json={"address": address, "password": password}
        )
        token.raise_for_status()
        self._token = token.json()["token"]
        self.address = address
        return address

    async def next_message(self) -> MailMessage | None:
        """The oldest message not returned before, or None if the inbox has nothing new."""
        if self._token is None:
            raise RuntimeError("mailbox not created")
        headers = {"Authorization": f"Bearer {self._token}"}
        listing = await self._client.get(f"{self._base}/messages", headers=headers)
        listing.raise_for_status()
        for item in listing.json().get("hydra:member", []):
            if item["id"] in self._seen:
                continue
            self._seen.add(item["id"])
            full = await self._client.get(f"{self._base}/messages/{item['id']}", headers=headers)
            full.raise_for_status()
            data = full.json()
            return MailMessage(data.get("subject", ""), data.get("text") or data.get("intro", ""))
        return None
