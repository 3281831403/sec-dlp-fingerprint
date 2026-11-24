"""Behavioral specification for the DLP fingerprint exercise."""

import pytest

from dlp.fingerprint import (
    dlp_batch,
    fingerprint,
    hash_shingle,
    match,
    normalize,
    shingles,
    similarity,
    validate_policy,
)


def test_normalize_removes_punctuation():
    assert normalize("数，据。安！全？外发检测") == "数据安全外发检测"
    assert normalize("Hello, WORLD!") == "hello world"
    assert normalize("数据安全外发检测，") == normalize("数据安全外发检测")


def test_normalize_collapses_whitespace():
    assert normalize("  数据\n安全\t外发   检测  ") == "数据 安全 外发 检测"
    assert normalize("A\n\nB\t C") == "a b c"


def test_shingles_are_rolling():
    assert shingles("abcdef", 3) == ["abc", "bcd", "cde", "def"]
    inserted = shingles("abXcdef", 3)
    assert inserted == ["abX", "bXc", "Xcd", "cde", "def"]
    assert set(shingles("abcdef", 3)) & set(inserted) == {"cde", "def"}


def test_shingles_short_text_is_empty_and_does_not_match():
    key = "short-document-key"
    size = 5
    assert shingles("abc", size) == []
    assert shingles("", size) == []

    short_fp = fingerprint("abc", key, size)
    assert short_fp == set()
    assert match(short_fp, {"short-policy": short_fp}, 0.1) == []


def test_hash_shingle_depends_on_key():
    first = hash_shingle("data-loss", "salt-one")
    assert isinstance(first, int)
    assert first == hash_shingle("data-loss", "salt-one")
    assert first != hash_shingle("data-loss", "salt-two")
    assert first != hash_shingle("data-leak", "salt-one")


def test_fingerprint_deduplicates_repeated_shingles():
    key = "dedupe-key"
    fp = fingerprint("abcabcabc", key, 3)
    expected = {
        hash_shingle("abc", key),
        hash_shingle("bca", key),
        hash_shingle("cab", key),
    }
    assert isinstance(fp, set)
    assert fp == expected
    assert len(fp) == 3


def test_similarity_uses_smaller_set_not_union():
    a = {1, 2, 3, 4}
    b = {3, 4, 5}
    assert similarity(a, b) == pytest.approx(2 / 3)
    assert similarity(b, a) == pytest.approx(2 / 3)

    short = {10, 11}
    long = {11, 12, 13, 14, 15}
    assert similarity(short, long) == pytest.approx(0.5)
    assert similarity(short, long) != pytest.approx(1 / 6)

    assert similarity(set(), {1, 2}) == 0.0
    assert similarity(set(), set()) == 0.0


def test_match_includes_threshold_boundary():
    doc = {1, 2}
    library = {
        "exact": {2, 3},
        "below": {4, 5},
        "none": {8, 9},
    }
    assert similarity(doc, library["exact"]) == pytest.approx(0.5)
    assert match(doc, library, 0.5) == ["exact"]
    assert match(doc, library, 0.5000001) == []


def test_validate_policy_rejects_small_shingle_size():
    valid = {"threshold": 0.8, "shingle_size": 5, "key": "policy-key"}
    assert validate_policy(valid) == []

    small_shingle = {"threshold": 0.8, "shingle_size": 2, "key": "policy-key"}
    assert validate_policy(small_shingle) == ["shingle_size_too_small"]

    unsafe = {"threshold": 0.4, "shingle_size": 2, "key": ""}
    assert validate_policy(unsafe) == [
        "threshold_too_low",
        "shingle_size_too_small",
        "missing_key",
    ]


def test_dlp_batch_keeps_documents_independent():
    key = "batch-key"
    size = 4
    sensitive = "alpha beta gamma delta epsilon zeta eta theta"
    benign = "red green blue cyan magenta yellow black white"
    library = {"policy-a": fingerprint(sensitive, key, size)}
    docs = {"first": sensitive, "second": benign}
    policy = {"threshold": 0.6, "shingle_size": size, "key": key}

    result = dlp_batch(docs, library, policy)
    assert result["first"] == ["policy-a"]
    assert result["second"] == []


def test_identical_documents_have_similarity_one():
    key = "identical-key"
    text = "数据安全外发检测需要稳定的文档指纹"
    first = fingerprint(text, key, 4)
    second = fingerprint(text, key, 4)
    assert first == second
    assert similarity(first, second) == 1.0


def test_paragraph_reordering_still_matches():
    paragraphs = [
        "数据安全团队要求所有外发文件必须经过文档指纹检测",
        "敏感内容识别会比对指纹库并记录命中分数和处置动作",
        "审计日志保存每次检测时间操作人和最终审批结果",
    ]
    original = "\n".join(paragraphs)
    reordered = "\n".join((paragraphs[2], paragraphs[0], paragraphs[1]))
    key = "reorder-key"
    size = 4
    library = {"policy": fingerprint(original, key, size)}

    assert match(fingerprint(reordered, key, size), library, 0.7) == ["policy"]


def test_small_edits_still_match():
    original = "数据安全团队要求所有外发文件必须经过文档指纹检测并记录最终结果"
    edited = "数据安全小组要求所有外发文件必须经过文档指纹检测并记录最终结果"
    key = "edit-key"
    size = 4
    library = {"policy": fingerprint(original, key, size)}

    assert match(fingerprint(edited, key, size), library, 0.7) == ["policy"]


def test_unrelated_document_does_not_match():
    sensitive = "数据安全团队要求所有外发文件必须经过文档指纹检测"
    unrelated = "周末天气预报显示多云转晴适合户外跑步和野餐"
    key = "unrelated-key"
    size = 4
    library = {"policy": fingerprint(sensitive, key, size)}

    assert match(fingerprint(unrelated, key, size), library, 0.2) == []


def test_batch_and_repeated_detection_are_consistent():
    key = "consistent-key"
    size = 4
    threshold = 0.6
    sensitive = "数据安全团队要求所有外发文件必须经过文档指纹检测"
    unrelated = "周末天气预报显示多云转晴适合户外跑步和野餐"
    library = {
        "z-policy": fingerprint(sensitive, key, size),
        "a-policy": fingerprint(sensitive, key, size),
        "other-policy": fingerprint(unrelated, key, size),
    }
    docs = {"doc-a": sensitive, "doc-b": unrelated}
    policy = {"threshold": threshold, "shingle_size": size, "key": key}

    batch = dlp_batch(docs, library, policy)
    single_a = dlp_batch({"doc-a": sensitive}, library, policy)["doc-a"]
    single_b = dlp_batch({"doc-b": unrelated}, library, policy)["doc-b"]

    assert batch["doc-a"] == single_a == ["a-policy", "z-policy"]
    assert batch["doc-b"] == single_b == ["other-policy"]

    first = match(fingerprint(sensitive, key, size), library, threshold)
    second = match(fingerprint(sensitive, key, size), library, threshold)
    assert first == second == ["a-policy", "z-policy"]