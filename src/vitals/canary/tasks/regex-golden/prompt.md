A product SKU code is defined by this regular expression, matched against the entire string
(a full match, not a partial/substring match):

    ^[A-Z]{3}-\d{4}(-[A-Z0-9]{2})?$

That is: exactly 3 uppercase letters, a hyphen, exactly 4 digits, and then an OPTIONAL suffix
of a hyphen followed by exactly 2 uppercase-letter-or-digit characters.

Below are 12 candidate strings, numbered 1 through 12. For each one, determine whether it is a
full match for the pattern above.

 1. ABC-1234
 2. ABC-1234-XY
 3. abc-1234
 4. AB-1234
 5. ABCD-1234
 6. ABC-123
 7. ABC-12345
 8. ABC-1234-X
 9. ABC-1234-XYZ
10. ABC-1234-12
11. ABC-1234-
12. ABC1234

Respond with exactly 12 characters and nothing else: one character per case, in order, with
no separators, spaces, or line breaks — `Y` if that case is a full match, `N` if it is not.
