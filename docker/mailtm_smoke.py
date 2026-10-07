"""Step F smoke test: mail.tm through the egress proxy (create inbox, poll, read a message).

Run inside the crawler container; prints timings and failure modes, never the token or password.
Usage: python docker/mailtm_smoke.py [wait_seconds].
Writes the address to runs/mailtm-smoke/address.txt so a sender can target it while this polls."""

import asyncio
import os
import sys
import time

import httpx

from scamhunter.agent.identity import MailTmMailbox, describe_message


async def main(wait: int) -> int:
    proxy = os.environ["EGRESS_PROXY"]
    t0 = time.monotonic()

    def log(msg: str) -> None:
        print(f"[{time.monotonic() - t0:6.1f}s] {msg}", flush=True)

    async with httpx.AsyncClient(proxy=proxy, timeout=20) as client:
        box = MailTmMailbox(client)
        t = time.monotonic()
        try:
            address = await box.create()
        except Exception as exc:  # report the failure mode; do not hide it
            log(f"create FAILED after {time.monotonic() - t:.2f}s: {type(exc).__name__}: {exc}")
            if isinstance(exc, httpx.HTTPStatusError):
                log(f"  status={exc.response.status_code} body={exc.response.text[:200]!r}")
            return 1
        log(f"create ok in {time.monotonic() - t:.2f}s: {address}")
        with open("/app/runs/mailtm-smoke/address.txt", "w") as f:
            f.write(address)
        polls = 0
        while time.monotonic() - t0 < wait:
            t = time.monotonic()
            try:
                msg = await box.next_message()
            except Exception as exc:
                log(f"poll FAILED: {type(exc).__name__}: {exc}")
                msg = None
            polls += 1
            dt = time.monotonic() - t
            if msg:
                log(f"poll #{polls} got a message ({dt:.2f}s round trip incl. fetch)")
                print(describe_message(msg.subject, msg.body), flush=True)
                return 0
            log(f"poll #{polls} empty ({dt:.2f}s)")
            await asyncio.sleep(5)
    log("no message before the deadline")
    return 2


sys.exit(asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 90)))
