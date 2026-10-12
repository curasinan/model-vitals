import json

from vitals.db import get_conn, init_db
from vitals.watch.change_points import check_and_record, snapshot


def _conn(tmp_path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def _paths(tmp_path, settings='{"hooks":{}}', plugins=None):
    s = tmp_path / "settings.json"
    s.write_text(settings, encoding="utf-8")
    p = tmp_path / "plugins.json"
    p.write_text(json.dumps(plugins if plugins is not None else {"version": 2, "plugins": {}}))
    v = tmp_path / "config.toml"
    v.write_text("")
    return s, p, v


def test_version_change_recorded_once(tmp_path):
    conn = _conn(tmp_path)
    s, p, v = _paths(tmp_path)
    snap1 = snapshot(s, p, v, version_cmd=lambda: "2.1.226 (Claude Code)")
    assert check_and_record(conn, snap1) == []
    snap2 = snapshot(s, p, v, version_cmd=lambda: "2.1.240 (Claude Code)")
    assert check_and_record(conn, snap2) == ["cc_version"]
    assert check_and_record(conn, snap2) == []
    row = conn.execute("SELECT * FROM change_points").fetchone()
    assert row["kind"] == "cc_version"
    assert "2.1.226" in row["old_value"] and "2.1.240" in row["new_value"]


def test_settings_edit_recorded(tmp_path):
    conn = _conn(tmp_path)
    s, p, v = _paths(tmp_path, '{"a":1}')
    check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x"))
    s.write_text('{"a":2}', encoding="utf-8")
    assert check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x")) == ["settings"]


def test_plugin_toggle_is_plugins_not_settings(tmp_path):
    conn = _conn(tmp_path)
    s, p, v = _paths(tmp_path, '{"enabledPlugins":{"a@b": true}}')
    check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x"))
    s.write_text('{"enabledPlugins":{"a@b": false}}', encoding="utf-8")
    assert check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x")) == ["plugins"]


def test_plugin_upgrade_recorded_with_a_readable_delta(tmp_path):
    conn = _conn(tmp_path)
    registry = {
        "version": 2,
        "plugins": {
            "example-plugin@vendor": [
                {"scope": "user", "version": "6.3.0", "gitCommitSha": "abc123"}
            ]
        },
    }
    s, p, v = _paths(tmp_path, plugins=registry)
    check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x"))
    registry["plugins"]["example-plugin@vendor"][0]["version"] = "6.4.0"
    p.write_text(json.dumps(registry), encoding="utf-8")
    assert check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x")) == ["plugins"]
    row = conn.execute("SELECT * FROM change_points WHERE kind='plugins'").fetchone()
    assert "6.3.0" in row["detail"] and "6.4.0" in row["detail"]


def test_unknown_plugin_version_is_tolerated(tmp_path):
    conn = _conn(tmp_path)
    registry = {
        "version": 2,
        "plugins": {"frontend-design@x": [{"scope": "user", "version": "unknown"}]},
    }
    s, p, v = _paths(tmp_path, plugins=registry)
    snap = snapshot(s, p, v, version_cmd=lambda: "x")
    assert snap["plugins_hash"]
    assert check_and_record(conn, snap) == []


def test_vitals_config_change_is_its_own_kind(tmp_path):
    conn = _conn(tmp_path)
    s, p, v = _paths(tmp_path)
    check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x"))
    v.write_text("[detect]\nh = 6.0\n", encoding="utf-8")
    assert check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x")) == ["vitals_config"]


def test_several_changes_at_once_are_all_recorded(tmp_path):
    conn = _conn(tmp_path)
    s, p, v = _paths(tmp_path)
    check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "2.1.226"))
    s.write_text('{"hooks":{"Stop":[]}}', encoding="utf-8")
    v.write_text("x = 1\n", encoding="utf-8")
    changed = check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "2.1.240"))
    assert set(changed) == {"cc_version", "settings", "vitals_config"}
    assert conn.execute("SELECT COUNT(*) FROM change_points").fetchone()[0] == 3


def test_missing_files_do_not_crash(tmp_path):
    conn = _conn(tmp_path)
    snap = snapshot(
        tmp_path / "nope.json",
        tmp_path / "nope2.json",
        tmp_path / "nope3.toml",
        version_cmd=lambda: "x",
    )
    assert check_and_record(conn, snap) == []


def test_version_lookup_failure_keeps_the_last_known_value(tmp_path):
    conn = _conn(tmp_path)
    s, p, v = _paths(tmp_path)
    check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "2.1.226"))

    def boom():
        raise OSError("claude not found")

    snap = snapshot(s, p, v, version_cmd=boom, conn=conn)
    assert snap["cc_version"] == "2.1.226"
    assert check_and_record(conn, snap) == []


def test_snapshot_is_stored_for_session_stamping(tmp_path):
    conn = _conn(tmp_path)
    s, p, v = _paths(tmp_path)
    check_and_record(conn, snapshot(s, p, v, version_cmd=lambda: "x"))
    stored = json.loads(
        conn.execute("SELECT value FROM vitals_kv WHERE key='snapshot'").fetchone()[0]
    )
    assert stored["settings_hash"] and stored["plugins_hash"]
