"""Document fingerprinting for DLP outbound inspection.

The ten false-negative defects are fixed in the order documented in the
exercise brief:

1.  normalize() deletes Unicode punctuation (punctuation insertion can no
    longer break fingerprint matches).
2.  normalize() collapses any run of whitespace into one single space and
    strips leading/trailing whitespace, so line breaks and extra spaces
    cannot shift rolling-shingle boundaries.
3.  shingles() uses a rolling window over every start position instead of
    fixed-boundary chunks, so one inserted character only disturbs the
    shingles that overlap it.
4.  shingles() returns [] for text shorter than the shingle size, so short
    documents produce an empty fingerprint instead of matching everything.
5.  hash_shingle() uses keyed HMAC-SHA256, so hashes cannot be reversed via
    dictionary lookup without the secret key.
6.  fingerprint() collects hashes into a set, de-duplicating repeated
    content so it cannot dilute the similarity score.
7.  similarity() divides the intersection by the *smaller* set size rather
    than the union, so short documents are not systematically under-scored.
8.  match() compares with ``>=`` so a score exactly equal to the threshold
    still counts as a hit (no off-by-one false negative).
9.  validate_policy() enforces the shingle-size lower bound (>= 3) together
    with the threshold lower bound and key presence.
10. dlp_batch() builds a fresh fingerprint and performs a fresh match for
    every document, never reusing another document's hit state.
"""

import hashlib
import hmac
import unicodedata


def normalize(text: str) -> str:
    """Lowercase text, remove punctuation, and collapse whitespace.

    Punctuation is deleted outright (never replaced by a space). Any run of
    whitespace characters becomes a single ASCII space and leading/trailing
    whitespace is stripped.
    """
    kept: list[str] = []
    for ch in text.lower():
        category = unicodedata.category(ch)
        # Defect 1: drop every Unicode punctuation character outright.
        if category.startswith("P"):
            continue
        # Defect 2: normalize all whitespace to one ASCII space first; the
        # final split/join collapses runs and trims the ends.
        if ch.isspace():
            kept.append(" ")
        else:
            kept.append(ch)
    return " ".join("".join(kept).split())


def shingles(text: str, size: int) -> list[str]:
    """Return all rolling character shingles; [] if the text is too short.

    The window advances one character at a time, so an insertion only
    invalidates the shingles that actually overlap it (defect 3). Text
    shorter than ``size`` yields no shingles at all (defect 4).
    """
    if size < 1 or len(text) < size:
        return []
    return [text[start : start + size] for start in range(len(text) - size + 1)]


def hash_shingle(shingle: str, key: str) -> int:
    """Return a deterministic keyed HMAC-SHA256 hash as an integer.

    The secret key is mixed into the HMAC, so the same shingle hashes
    differently under different keys and an attacker without the key cannot
    reverse the hash with a dictionary attack (defect 5).
    """
    mac = hmac.new(
        key.encode("utf-8"),
        shingle.encode("utf-8"),
        hashlib.sha256,
    )
    return int.from_bytes(mac.digest(), "big")


def fingerprint(text: str, key: str, size: int) -> set[int]:
    """Build a de-duplicated set of keyed shingle hashes for a document."""
    normalized = normalize(text)
    # Defect 6: a set de-duplicates repeated shingles so repeated content
    # cannot inflate the document and dilute similarity. Defect 4 follows
    # from shingles(): short text yields an empty set, never a false match.
    return {hash_shingle(shingle, key) for shingle in shingles(normalized, size)}


def similarity(a: set[int], b: set[int]) -> float:
    """Intersection size divided by the smaller set size; 0.0 if empty.

    Using the smaller set (overlap coefficient) instead of the union (Jaccard)
    prevents short documents from being systematically under-scored when
    they are fully contained in a longer library fingerprint (defect 7).
    """
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def match(doc: set[int], library: dict[str, set[int]], threshold: float) -> list[str]:
    """Return sorted library names whose similarity is at least the threshold.

    The comparison is inclusive (``>=``) so a score exactly equal to the
    threshold is reported instead of slipping through (defect 8). The
    library mapping and its fingerprint sets are only read, never mutated.
    """
    return sorted(
        name
        for name, stored in library.items()
        if similarity(doc, stored) >= threshold
    )


def validate_policy(policy: dict) -> list[str]:
    """Return deterministic issue codes for an unsafe DLP matching policy.

    Codes are emitted in a fixed order: threshold_too_low,
    shingle_size_too_small, missing_key. Missing fields fail closed (defect 9
    adds the shingle-size floor of 3 alongside the other two checks).
    """
    issues: list[str] = []
    if policy.get("threshold", 0.0) < 0.5:
        issues.append("threshold_too_low")
    if policy.get("shingle_size", 0) < 3:
        issues.append("shingle_size_too_small")
    if not policy.get("key"):
        issues.append("missing_key")
    return issues


def dlp_batch(
    docs: dict[str, str],
    library: dict[str, set[int]],
    policy: dict,
) -> dict[str, list[str]]:
    """Inspect every document independently against a pre-fingerprinted library.

    Each document gets its own freshly computed fingerprint and its own
    match() call with no shared mutable cursor, so one document's hits can
    never leak into the next document's result (defect 10).
    """
    key = policy["key"]
    size = policy["shingle_size"]
    threshold = policy["threshold"]

    results: dict[str, list[str]] = {}
    for name, text in docs.items():
        doc_fingerprint = fingerprint(text, key, size)
        results[name] = match(doc_fingerprint, library, threshold)
    return results
