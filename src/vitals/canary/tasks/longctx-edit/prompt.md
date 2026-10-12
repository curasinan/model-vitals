`module.py` in this workspace is a large generated Python module (about 3,000 lines). It
defines one constant, `MAX_POOL_SIZE`, near the top of the file, currently set to `12`.

Elsewhere in the file there are exactly three *usages* of this constant: three different
functions, each containing a line that ends with the exact trailing comment
`# MAX_POOL_SIZE` and hardcodes the constant's current numeric value on that same line.
That trailing comment is the only thing marking a real usage -- the file also contains many
unrelated numeric literals that happen to equal `12` for other reasons, and those must be
left alone.

Change `MAX_POOL_SIZE`'s value from `12` to `48`, and update the literal number on each of
those three marked usage lines from `12` to `48` as well, so the file stays internally
consistent (its definition and every usage agreeing on the same value).

Rules, followed exactly:
- Change only the constant's definition line and the three lines that end in the exact
  trailing comment `# MAX_POOL_SIZE`. Do not change anything else in the file: no other
  line, no other numeral `12` that lacks that trailing comment, no formatting, no
  reordering, no added or removed blank lines.
- Only edit `module.py`. Do not add or modify any other file.
