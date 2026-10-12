Write a pytest test file named `test_slugify.py` for the `slugify` function defined in
`slugify.py` (same directory).

`slugify(text)` is supposed to produce a URL-safe slug: lowercase, ASCII only (accented
characters stripped to their closest plain-ASCII letter), with every run of
non-alphanumeric characters (spaces, punctuation, repeated separators) collapsed to a
single hyphen, and no leading or trailing hyphen.

Your tests must cover, at minimum: mixed-case input, whitespace, punctuation, accented
Unicode characters, and leading/trailing or repeated separators — and must assert on the
exact string `slugify` returns in each case, not merely that it returns a string or a
non-empty value.

Write only `test_slugify.py`. Do not modify `slugify.py` or add any other file.
