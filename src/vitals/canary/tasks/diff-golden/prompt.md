`report.py` builds each line of a text report using old-style `%` string formatting: six
functions, each with exactly one `return` statement built this way.

Convert every one of these six `%`-formatted strings to an equivalent f-string. The text
each function returns must be byte-for-byte identical to what the current code produces for
the same inputs — you are only changing *how* each string is built, never its content, its
variable names, or any other code in the file.

Rules, followed exactly:
- Do not change anything in the file except the six `return` statements' string
  construction. Function signatures, variable names, computations, and all other lines
  (including blank lines and comments) stay exactly as they are.
- Use double-quoted f-strings (`f"..."`), matching the double quotes already used
  throughout the file.
- Preserve the format specifiers where they affect output: `%d` becomes a plain `{name}`
  placeholder, `%.2f` becomes `{name:.2f}`, and `%.1f%%` becomes `{name:.1f}%` (an f-string
  needs no escaping for a literal `%`, unlike `%`-style formatting).
- Do not reorder, rename, add, or remove any function, blank line, or comment.

Worked example, for a line not in this file: `"Hello %s, you are %d" % (name, age)`
becomes `f"Hello {name}, you are {age}"`.

Only edit `report.py`. Do not add or modify any other file.
