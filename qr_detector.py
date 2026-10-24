
import os

import cv2
import numpy as np


MAX_IMAGE_SIZE = 10 * 1024 * 1024

SUPPORTED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".webp",
    ".tif",
    ".tiff",
}


def decode_qr(uploaded_file) -> str | None:
    """
    Decode a QR code from an uploaded image.

    Returns the decoded text or URL, or None if decoding fails.
    Never opens or fetches the decoded destination.
    """
    if uploaded_file is None:
        return None

    try:
        if hasattr(uploaded_file, "getvalue"):
            image_bytes = uploaded_file.getvalue()
        elif hasattr(uploaded_file, "read"):
            image_bytes = uploaded_file.read()
        else:
            return None

        if not isinstance(image_bytes, (bytes, bytearray)):
            return None

        if not image_bytes or len(image_bytes) > MAX_IMAGE_SIZE:
            return None

        filename = getattr(uploaded_file, "name", None)

        if filename:
            extension = os.path.splitext(filename)[1].lower()
            if extension not in SUPPORTED_EXTENSIONS:
                return None

        image_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

        if image is None or image.size == 0:
            return None

        detector = cv2.QRCodeDetector()
        decoded_text, points, _ = detector.detectAndDecode(image)

        if points is None or not decoded_text:
            return None

        decoded_text = decoded_text.strip()
        return decoded_text or None

    except Exception:
        return None
