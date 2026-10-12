import pytest


def test_config_defaults_and_env_override(tmp_path, monkeypatch):
    from vitals.config import load

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    cfg = load()
    assert cfg.data_dir == tmp_path
    assert cfg.db_path == tmp_path / "vitals.db"
    assert cfg.spool_dir == tmp_path / "spool"
    assert cfg.reports_dir == tmp_path / "reports"
    assert cfg.otlp_port == 4318
    assert cfg.canary.model == "claude-sonnet-5"
    assert cfg.canary.runs_per_task == 2
    assert cfg.canary.daily_budget_usd == 6.0
    assert cfg.detect.h == 5.0
    assert cfg.detect.k == 0.5


def test_config_toml_overrides(tmp_path, monkeypatch):
    from vitals.config import load

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    (tmp_path / "config.toml").write_text(
        '[canary]\nmodel = "claude-haiku-4-5"\ndaily_budget_usd = 2.5\n'
    )
    cfg = load()
    assert cfg.canary.model == "claude-haiku-4-5"
    assert cfg.canary.daily_budget_usd == 2.5
    assert cfg.detect.h == 5.0


def test_unknown_key_raises_naming_the_key(tmp_path, monkeypatch):
    from vitals.config import load

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    (tmp_path / "config.toml").write_text("[detect]\nhh = 9\n")
    with pytest.raises(ValueError, match="hh"):
        load()


def test_channels_table_is_free_form(tmp_path, monkeypatch):
    from vitals.config import load

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    (tmp_path / "config.toml").write_text('[channels.telegram]\nenabled = true\nchat_id = "123"\n')
    cfg = load()
    assert cfg.channels["telegram"]["chat_id"] == "123"


def test_channel_entry_that_is_not_a_table_is_rejected_naming_the_key(tmp_path, monkeypatch):
    from vitals.config import load

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    (tmp_path / "config.toml").write_text("[channels]\ndesktop = true\n")

    with pytest.raises(ValueError, match=r"channels\.desktop"):
        load()


def test_channel_entry_error_names_the_type_it_actually_got(tmp_path, monkeypatch):
    from vitals.config import load

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    (tmp_path / "config.toml").write_text('[channels]\nntfy = "my-topic"\n')

    with pytest.raises(ValueError, match="str"):
        load()


def test_several_valid_channel_tables_still_load(tmp_path, monkeypatch):
    from vitals.config import load

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    (tmp_path / "config.toml").write_text(
        '[channels.desktop]\nenabled = true\n[channels.ntfy]\nenabled = false\ntopic_env = "X"\n'
    )

    cfg = load()

    assert cfg.channels["desktop"]["enabled"] is True
    assert cfg.channels["ntfy"]["topic_env"] == "X"


def test_home_data_dir_uses_the_new_name_by_default(tmp_path, monkeypatch):
    from vitals.config import home_data_dir

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert home_data_dir() == tmp_path / ".model-vitals"


def test_home_data_dir_keeps_using_an_existing_legacy_install(tmp_path, monkeypatch):
    from vitals.config import home_data_dir

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / ".claude-vitals").mkdir()
    assert home_data_dir() == tmp_path / ".claude-vitals"
    (tmp_path / ".model-vitals").mkdir()
    assert home_data_dir() == tmp_path / ".model-vitals"
