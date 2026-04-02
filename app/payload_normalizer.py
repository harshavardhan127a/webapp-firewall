"""
Deep Payload Normalization Engine (H1 Fix)
Processes input through multiple decoding layers to defeat encoding evasion.

Layers:
1. URL decoding (single + double + triple)
2. HTML entity decoding
3. Unicode NFKC normalization
4. Unicode homoglyph translation (Cyrillic/fullwidth → ASCII)
5. Hex string decoding (0x41424344 → ABCD)
6. Base64 detection and decoding
7. SQL comment removal (/**/, --, #)
8. Whitespace normalization
9. Case normalization (lowercase)
"""
import re
import html
import base64
import urllib.parse
import unicodedata
from typing import List, Set


class PayloadNormalizer:
    """Multi-layer payload normalization to defeat encoding evasion attacks"""

    # SQL comment patterns to strip
    _SQL_BLOCK_COMMENTS = re.compile(r'/\*.*?\*/', re.DOTALL)
    _SQL_INLINE_COMMENTS = re.compile(r'--[^\n]*')
    _SQL_HASH_COMMENTS = re.compile(r'#[^\n]*')

    # Whitespace normalization
    _MULTI_WHITESPACE = re.compile(r'\s+')

    # Hex string pattern (e.g., 0x414243)
    _HEX_PATTERN = re.compile(r'0x([0-9a-fA-F]{2,})')

    # Base64 detection (at least 16 chars, valid Base64 alphabet, optional padding)
    _B64_PATTERN = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

    # Unicode confusable characters → ASCII equivalents
    # Covers fullwidth forms, Cyrillic homoglyphs, and other lookalikes
    _HOMOGLYPHS = str.maketrans({
        # Fullwidth ASCII variants
        '\uff1c': '<', '\uff1e': '>', '\uff07': "'", '\uff02': '"',
        '\uff08': '(', '\uff09': ')', '\uff1b': ';', '\uff5c': '|',
        '\uff0f': '/', '\uff3c': '\\', '\uff0e': '.', '\uff05': '%',
        '\uff03': '#', '\uff06': '&', '\uff0d': '-', '\uff0b': '+',
        '\uff1d': '=', '\uff20': '@', '\uff3b': '[', '\uff3d': ']',
        # Typographic quotes
        '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
        # Math operators that look like ASCII
        '\u2215': '/', '\u2216': '\\',
        # Cyrillic confusables (look identical to Latin in many fonts)
        '\u0435': 'e', '\u0430': 'a', '\u043e': 'o',
        '\u0440': 'p', '\u0441': 'c', '\u0445': 'x',
        '\u0443': 'y', '\u0456': 'i', '\u044a': 'b',
        # Other lookalikes
        '\u0131': 'i',  # Dotless i
        '\u0237': 'j',  # Dotless j
    })

    @classmethod
    def normalize(cls, data: str, max_depth: int = 3) -> List[str]:
        """
        Produce all normalized forms of input through recursive decoding.

        Args:
            data: Raw input string
            max_depth: Maximum recursion depth for layered decoding

        Returns:
            Deduplicated list of all decoded versions (including original)
        """
        if not data:
            return [data] if data is not None else []

        seen: Set[str] = set()
        results: List[str] = []

        def _add(s: str):
            if s and s not in seen:
                seen.add(s)
                results.append(s)

        _add(data)

        for _depth in range(max_depth):
            new_forms = []

            for form in list(results):
                # Layer 1: URL decode
                try:
                    decoded = urllib.parse.unquote(form)
                    if decoded != form:
                        new_forms.append(decoded)
                except Exception:
                    pass

                # Layer 2: HTML entity decode
                try:
                    decoded = html.unescape(form)
                    if decoded != form:
                        new_forms.append(decoded)
                except Exception:
                    pass

                # Layer 3: Unicode NFKC normalization
                try:
                    decoded = unicodedata.normalize('NFKC', form)
                    if decoded != form:
                        new_forms.append(decoded)
                except Exception:
                    pass

                # Layer 4: Unicode homoglyph translation
                translated = form.translate(cls._HOMOGLYPHS)
                if translated != form:
                    new_forms.append(translated)

                # Layer 5: Hex string decoding (0x4142 → AB)
                try:
                    decoded = cls._HEX_PATTERN.sub(
                        lambda m: bytes.fromhex(m.group(1)).decode('utf-8', errors='ignore'),
                        form
                    )
                    if decoded != form:
                        new_forms.append(decoded)
                except Exception:
                    pass

                # Layer 6: Base64 decoding (only for clearly Base64 blobs)
                cls._try_base64_decode(form, new_forms)

                # Layer 7: SQL comment removal
                stripped = cls._SQL_BLOCK_COMMENTS.sub(' ', form)
                stripped = cls._SQL_INLINE_COMMENTS.sub('', stripped)
                stripped = cls._SQL_HASH_COMMENTS.sub('', stripped)
                if stripped.strip() != form.strip():
                    new_forms.append(stripped.strip())

                # Layer 8: Whitespace normalization
                normalized = cls._MULTI_WHITESPACE.sub(' ', form).strip()
                if normalized != form:
                    new_forms.append(normalized)

                # Layer 9: Case normalization (lowercase)
                lowered = form.lower()
                if lowered != form:
                    new_forms.append(lowered)

            for nf in new_forms:
                _add(nf)

        return results

    @classmethod
    def _try_base64_decode(cls, data: str, results: list):
        """
        Detect and decode Base64 encoded segments.
        Only decodes if the result contains printable ASCII content.
        """
        for match in cls._B64_PATTERN.finditer(data):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                # Only include if it looks like meaningful text (has letters)
                if decoded and sum(1 for c in decoded if c.isalpha()) > len(decoded) * 0.3:
                    results.append(decoded)
            except Exception:
                pass
