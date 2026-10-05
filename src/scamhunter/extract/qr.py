"""Decode QR codes from images and canvases."""

import io

import zxingcpp
from PIL import Image


def decode_qr(image_bytes: bytes) -> list[str]:
    """Text of every QR code in an image (a full-page screenshot covers <img>, <canvas> and
    CSS backgrounds at once). Unreadable images yield an empty list, never an exception."""
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
    except Exception:  # noqa: BLE001 - hostile or truncated images must not crash extraction
        return []
    results = zxingcpp.read_barcodes(image, formats=zxingcpp.BarcodeFormat.QRCode)
    return [r.text for r in results if r.valid and r.text]
