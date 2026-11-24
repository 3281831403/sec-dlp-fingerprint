"""Document fingerprinting stubs for the DLP false-negative exercise."""


def normalize(text: str) -> str:
    """Lowercase text, remove punctuation, and collapse whitespace."""
    raise NotImplementedError


def shingles(text: str, size: int) -> list[str]:
    """Return all rolling character shingles; return [] if text is too short."""
    raise NotImplementedError


def hash_shingle(shingle: str, key: str) -> int:
    """Hash one shingle with a secret key so plaintext cannot be dictionary-looked-up."""
    raise NotImplementedError


def fingerprint(text: str, key: str, size: int) -> set[int]:
    """Build a de-duplicated set of keyed shingle hashes for a document."""
    raise NotImplementedError


def similarity(a: set[int], b: set[int]) -> float:
    """Return intersection size divided by the smaller set size, or 0.0 if empty."""
    raise NotImplementedError


def match(doc: set[int], library: dict[str, set[int]], threshold: float) -> list[str]:
    """Return sorted matching library names whose similarity is at least threshold."""
    raise NotImplementedError


def validate_policy(policy: dict) -> list[str]:
    """Return deterministic issue codes for an unsafe DLP matching policy."""
    raise NotImplementedError


def dlp_batch(
    docs: dict[str, str],
    library: dict[str, set[int]],
    policy: dict,
) -> dict[str, list[str]]:
    """Inspect every document independently against a pre-fingerprinted library."""
    raise NotImplementedError