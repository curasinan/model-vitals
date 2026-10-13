import time

import pytest

from vitals.report.redact import redact_report, redact_text


def test_anthropic_key():
    assert "sk-ant-" not in redact_text("key=sk-ant-api03-AbCd1234EfGh5678")


def test_key_split_across_line_break_is_a_known_gap():
    out = redact_text("sk-ant-api03-AbCd1234\nEfGh5678EfGh5678EfGh5678")
    assert "<REDACTED:key>" in out
    assert "AbCd1234" not in out
    assert "EfGh5678EfGh5678EfGh5678" in out


def test_github_pat_classic():
    out = redact_text("token ghp_" + "A" * 36)
    assert "ghp_" not in out
    assert "<REDACTED:key>" in out


def test_github_pat_fine_grained():
    out = redact_text("github_pat_" + "A1b2C3" * 6)
    assert "github_pat_" not in out
    assert "<REDACTED:key>" in out


def test_aws_access_key():
    out = redact_text("AKIA" + "Q" * 16 + " in .env")
    assert "AKIA" not in out
    assert "<REDACTED:key>" in out


def test_slack_token():
    out = redact_text("xox" + "b-1234567890-abcdefghijklmnop")
    assert "xoxb-" not in out
    assert "<REDACTED:key>" in out


def test_jwt():
    out = redact_text(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    assert out.count("<REDACTED") == 1
    assert out == "<REDACTED:jwt>"


def test_jwt_embedded_in_header_line():
    out = redact_text(
        "Authorization: Bearer "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    assert out.count("<REDACTED") == 1
    assert "<REDACTED:jwt>" in out
    assert "eyJ" not in out


def test_pem_private_key_block():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz\n"
        "ZYXWVUTSRQPONMLKJIHGFEDCBA0987654321zyxwvutsrqponmlk\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    out = redact_text(f"leaked:\n{pem}\nrest of log")
    assert "MIIEpAIBAAKCAQEA" not in out
    assert out.count("<REDACTED:privkey>") == 1
    assert "rest of log" in out


def test_assignment_password():
    out = redact_text("password = hunter2")
    assert "hunter2" not in out
    assert out == "password = <REDACTED:assignment>"


def test_assignment_api_key_equals():
    out = redact_text("api_key=abcdef123456")
    assert "abcdef123456" not in out
    assert out == "api_key=<REDACTED:assignment>"


def test_assignment_secret_colon():
    out = redact_text("secret: topsecretvalue")
    assert "topsecretvalue" not in out
    assert "secret" in out.lower()


def test_authorization_bearer_full_token_redacted():
    token = "sk_" + "live_abcdefghijklmnopqrstuvwxyz"
    out = redact_text("Authorization: Bearer " + token)
    assert token not in out
    assert "Authorization" in out


def test_doubled_bearer_still_redacted():
    out = redact_text("Authorization: Bearer Bearer abc123XYZ")
    assert "abc123XYZ" not in out
    assert "<REDACTED:assignment>" in out


def test_doubled_bearer_equals_form_still_redacted():
    out = redact_text("token = Bearer Bearer realSecretValue")
    assert "realSecretValue" not in out
    assert "<REDACTED:assignment>" in out


def test_chained_assignments_stay_independent():
    out = redact_text("token=abc;region=xyz")
    assert out == "token=<REDACTED:assignment>;region=xyz"


def test_chained_assignments_comma_separated():
    out = redact_text("api_key=abc123,region=us-east-1")
    assert "abc123" not in out
    assert "region=us-east-1" in out


def test_single_value_with_internal_commas_is_a_known_limitation_not_a_bug():
    out = redact_text("secret=part1,part2,part3")
    assert "<REDACTED:assignment>" in out
    assert "part1" not in out
    assert "part2,part3" in out


def test_bare_trigger_word_without_separator_untouched():
    src = "password reset instructions were sent to your inbox"
    assert redact_text(src) == src


def test_json_quoted_authorization_bearer_was_a_live_leak_now_fixed():
    out = redact_text('{"Authorization": "Bearer abc123XYZsecretvalue"}')
    assert "abc123XYZsecretvalue" not in out
    assert "<REDACTED:assignment>" in out
    assert "Authorization" in out


def test_json_single_quoted_key_with_spaced_colon_redacted():
    out = redact_text("{'api_key' : 'realsecretvalue123'}")
    assert "realsecretvalue123" not in out
    assert "<REDACTED:assignment>" in out
    assert "api_key" in out


def test_bare_token_equals_value_form_still_redacted():
    out = redact_text("token=plainsecretvalue123")
    assert "plainsecretvalue123" not in out
    assert "<REDACTED:assignment>" in out


def test_escaped_quote_json_secret_was_a_live_leak_now_fixed():
    raw = '{"tool_response": "{\\"token\\": \\"s3cr3tvalue\\"}"}'
    assert '\\"token\\"' in raw
    out = redact_text(raw)
    assert "s3cr3tvalue" not in out
    assert "<REDACTED:assignment>" in out


def test_escaped_quote_json_secret_other_trigger_words():
    for word in ("api_key", "password", "secret", "Authorization"):
        raw = '{"x": "{\\"%s\\": \\"leakme12345\\"}"}' % word
        out = redact_text(raw)
        assert "leakme12345" not in out, word
        assert "<REDACTED:assignment>" in out, word


def test_escaped_quote_json_bearer_value_redacted():
    raw = '{"payload": "{\\"Authorization\\": \\"Bearer abc123XYZsecret\\"}"}'
    out = redact_text(raw)
    assert "abc123XYZsecret" not in out
    assert "<REDACTED:assignment>" in out


def test_email():
    out = redact_text("mail curasinan9@gmail.com")
    assert "curasinan9@gmail.com" not in out
    assert out == "mail <REDACTED:email>"


def test_windows_userdir():
    out = redact_text(r"at C:\Users\asus\proj\a.py")
    assert "asus" not in out
    assert out == r"at <REDACTED:path>\proj\a.py"


def test_windows_userdir_lowercase_drive_and_users():
    out = redact_text(r"at c:\users\asus\proj\a.py")
    assert "asus" not in out
    assert "<REDACTED:path>" in out


def test_windows_userdir_mixed_case():
    out = redact_text(r"at C:\Users\Asus\proj\a.py")
    assert "Asus" not in out
    assert "<REDACTED:path>" in out


def test_posix_home_path():
    out = redact_text("at /home/alice/project/file.py")
    assert "alice" not in out
    assert out == "at <REDACTED:path>/project/file.py"


def test_posix_users_path_macos_style():
    out = redact_text("at /Users/bob/repo/main.py")
    assert "bob" not in out
    assert "<REDACTED:path>" in out


def test_forward_slash_windows_userdir_lowercase_leaked_the_username():
    out = redact_text("at c:/users/asus/proj/a.py")
    assert "asus" not in out
    assert "<REDACTED:path>" in out


def test_posix_home_uppercase_variant_also_redacted():
    out = redact_text("at /HOME/alice/project/file.py")
    assert "alice" not in out
    assert "<REDACTED:path>" in out


def test_non_loopback_ipv4_redacted():
    out = redact_text("client connected from 203.0.113.42")
    assert "203.0.113.42" not in out
    assert out == "client connected from <REDACTED:ip>"


def test_private_lan_ipv4_redacted():
    out = redact_text("bind 192.168.1.5:9000")
    assert "192.168.1.5" not in out


def test_loopback_ipv4_untouched():
    s = "http://127.0.0.1:4318"
    assert redact_text(s) == s


def test_loopback_range_untouched():
    assert redact_text("127.0.0.5 is still loopback") == "127.0.0.5 is still loopback"


def test_zero_ipv4_untouched():
    assert redact_text("listening on 0.0.0.0:8080") == "listening on 0.0.0.0:8080"


def test_ipv6_loopback_untouched():
    assert redact_text("connect ::1 fallback") == "connect ::1 fallback"


def test_entropy_catchall():
    assert "9fXk2LmQ8vRt4Zw7Yb3NcJd6Hs1TpAe5" not in redact_text(
        "blob 9fXk2LmQ8vRt4Zw7Yb3NcJd6Hs1TpAe5"
    )


def test_entropy_catchall_below_length_floor_survives():
    token = "9fXk2LmQ8vRt4Zw7Yb3N"
    assert len(token) < 24
    assert redact_text(f"short {token} value") == f"short {token} value"


def test_plain_code_untouched():
    src = "def haversine_km(lat1, lon1):\n    return 2 * R * asin(sqrt(h))"
    assert redact_text(src) == src


def test_plain_js_untouched():
    src = "const result = items.filter(x => x.active).map(x => x.id);"
    assert redact_text(src) == src


def test_long_snake_case_identifier_survives():
    src = "calculate_effective_context_window_size_for_current_session = 1"
    assert redact_text(src) == src


def test_git_sha_in_commit_message_survives():
    src = "Fixes regression introduced in a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    assert redact_text(src) == src


def test_uuid_survives():
    src = "request_id=550e8400-e29b-41d4-a716-446655440000"
    assert redact_text(src) == src


def test_iso_timestamp_survives():
    src = "started at 2026-08-25T14:30:00+00:00 and finished later"
    assert redact_text(src) == src


def test_file_path_of_normal_words_survives():
    src = "see src/vitals/report/redact for the implementation"
    assert redact_text(src) == src


def test_low_entropy_base64_fixture_survives():
    src = "buffer = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    assert redact_text(src) == src


def test_short_base64_value_survives_by_length_floor():
    src = "data=U2FsdGVkX1+abc123=="
    assert redact_text(src) == src


def test_idempotent_on_already_redacted_text():
    once = redact_text("token=" + "Z" * 40)
    twice = redact_text(once)
    assert once == twice


def test_redacted_tokens_do_not_trip_entropy_rule():
    tags = "<REDACTED:key> <REDACTED:jwt> <REDACTED:privkey> <REDACTED:entropy>"
    assert redact_text(tags) == tags


def test_redact_report_walks_nested_strings():
    obj = {
        "session": {"user_email": "curasinan9@gmail.com"},
        "events": [
            {"msg": "path C:\\Users\\asus\\a.py", "count": 3},
            {"msg": "ok", "score": 1.5, "flag": True, "none": None},
        ],
    }
    out = redact_report(obj)
    assert "curasinan9@gmail.com" not in out["session"]["user_email"]
    assert "asus" not in out["events"][0]["msg"]
    assert out["events"][0]["count"] == 3
    assert out["events"][1] == {"msg": "ok", "score": 1.5, "flag": True, "none": None}


def test_redact_report_preserves_dict_keys():
    obj = {"api_key": "sk-ant-api03-AbCd1234EfGh5678"}
    out = redact_report(obj)
    assert "api_key" in out
    assert "sk-ant-" not in out["api_key"]


def test_pem_pattern_no_catastrophic_backtracking_on_large_input():
    chunk = "-----BEGIN RSA PRIVATE KEY----- " + ("x" * 200) + " "
    big = chunk * 4000
    start = time.monotonic()
    result = redact_text(big)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"redact_text took {elapsed:.2f}s on adversarial PEM input"
    assert isinstance(result, str)


def test_email_pattern_no_catastrophic_backtracking_on_large_input():
    big = "1." * 150000
    start = time.monotonic()
    result = redact_text(big)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"redact_text took {elapsed:.2f}s on adversarial email-shaped input"
    assert isinstance(result, str)


def test_jwt_pattern_no_catastrophic_backtracking_on_large_input():
    chunk = "eyJ" + ("A" * 60)
    big = chunk * 8000
    start = time.monotonic()
    result = redact_text(big)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"redact_text took {elapsed:.2f}s on adversarial JWT-shaped input"
    assert isinstance(result, str)


def test_module_docstring_states_the_entropy_rule_cannot_fire_on_hex():
    import vitals.report.redact as redact_mod

    doc = redact_mod.__doc__ or ""
    assert "4.0" in doc
    assert "hex" in doc.lower()
    assert "backstop" in doc.lower()


def test_hex_tokens_are_structurally_below_the_entropy_threshold():
    from vitals.report.redact import _ENTROPY_THRESHOLD, _shannon_entropy

    uniform_hex = "0123456789abcdef" * 8
    assert _shannon_entropy(uniform_hex) == 4.0
    assert _shannon_entropy(uniform_hex) < _ENTROPY_THRESHOLD
    assert "<REDACTED:entropy>" not in redact_text(uniform_hex)


def test_assignment_pattern_no_catastrophic_backtracking_on_escaped_json(capsys):
    big = '{"tool_response": "{\\"token\\": \\"s3cr3tvalue\\"}"} ' * 30000
    start = time.monotonic()
    result = redact_text(big)
    elapsed = time.monotonic() - start
    with capsys.disabled():
        print(f"\n[redactor timing] escaped-quote JSON hostile input: {elapsed:.2f}s")
    assert elapsed < 5.0, f"redact_text took {elapsed:.2f}s on escaped-quote JSON input"
    assert "s3cr3tvalue" not in result


def test_assignment_pattern_no_catastrophic_backtracking_on_doubled_bearer():
    big = "Authorization: Bearer Bearer abc123XYZ realistic-value-here " * 30000
    start = time.monotonic()
    result = redact_text(big)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"redact_text took {elapsed:.2f}s on repeated doubled-Bearer input"
    assert "abc123XYZ" not in result


_HEX40 = "ab12" * 10


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("DB_PASSWORD=hunter2", "hunter2"),
        ("PGPASSWORD=s3cretpw", "s3cretpw"),
        ('{"client_secret": "Zx9-short-ish"}', "Zx9-short-ish"),
        ('{"refresh_token": "1//0gAbCdEf"}', "1//0gAbCdEf"),
        ('{"accessToken": "' + _HEX40 + '"}', _HEX40),
        ('{"dbPassword": "hunter2"}', "hunter2"),
        ('"private_key_id": "' + _HEX40 + '"', _HEX40),
        ("https://x.example/cb?access_token=ya29.a0AfH6SMB&x=1", "ya29.a0AfH6SMB"),
        ("$env:VITALS_CORPUS_HMAC_KEY = '" + _HEX40 + "'", _HEX40),
        ("Cookie: sessionid=abc123def; csrftoken=zzz999", "abc123def"),
        ("Cookie: sessionid=abc123def; csrftoken=zzz999", "zzz999"),
        ("https://acct.blob.example/c?sv=2024&sig=Ab%2Bcd123", "Ab%2Bcd123"),
        ("mysql --password hunter2 -h db", "hunter2"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ],
)
def test_named_secrets_in_compound_names_are_redacted(text, secret):
    assert secret not in redact_text(text)


@pytest.mark.parametrize(
    ("text", "user"),
    [
        (r'"C:\\Users\\alice.smith\\proj\\x.py"', "alice.smith"),
        (r"D:\Users\alice\proj", "alice"),
        (r"C:\Users\John Smith\Documents\a.txt", "Smith"),
        (r"\\wsl$\Ubuntu\home\alice\proj", "alice"),
        ("C%3A%5CUsers%5Calice%5Cproj", "alice"),
        ("mail alice.smith%40example.com", "alice.smith"),
    ],
)
def test_user_paths_in_escaped_and_encoded_forms_are_redacted(text, user):
    assert user not in redact_text(text)


def test_pgp_private_key_block_is_redacted():
    body = "lQOYBF" + "q" * 40
    text = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{body}\n-----END PGP PRIVATE KEY BLOCK-----"
    assert "PRIVATE KEY BLOCK" not in redact_text(text)


@pytest.mark.parametrize(
    "text",
    [
        "output_tokens=1500 input_tokens: 20",
        "max_tokens=4096",
        "design=compact author=alice",
        "session #1, turn #2",
    ],
)
def test_counts_and_ordinary_words_are_left_alone(text):
    assert redact_text(text) == text
