from slugify import slugify


def test_lowercases_mixed_case_input():
    assert slugify("Hello World") == "hello-world"


def test_replaces_whitespace_with_hyphen():
    assert slugify("  spaced   out  ") == "spaced-out"


def test_replaces_punctuation_with_hyphen():
    assert slugify("Wait... what?!") == "wait-what"


def test_strips_leading_and_trailing_hyphens():
    assert slugify("--edge--") == "edge"


def test_strips_accents_from_unicode_text():
    assert slugify("Café déjà vu") == "cafe-deja-vu"


def test_collapses_consecutive_separators_into_one():
    assert slugify("a---b   c") == "a-b-c"
