import os

from cerberus.config import get_model_kwargs, load_config


def test_config_interpolation(tmp_path, monkeypatch):
    monkeypatch.setattr("cerberus.config._load_dotenv", lambda *a, **k: None)
    p = tmp_path / "c.yaml"
    p.write_text("base_url: ${BASE_URL:-http://x}\nhunter_model: ${HUNTER_MODEL:-h}\napi_key_env: API_KEY\n")
    os.environ.pop("BASE_URL", None)
    cfg = load_config(p)
    assert cfg["base_url"] == "http://x"
    kw = get_model_kwargs(cfg, "hunter")
    assert "model" in kw and "base_url" in kw


def test_effort_levels(tmp_path, monkeypatch):
    from cerberus.config import EFFORT_RANK, get_reasoning_kwargs, load_config, reset_config
    p = tmp_path / "c.yaml"
    p.write_text("effort: ${EFFORT:-medium}\n")
    monkeypatch.setenv("EFFORT", "low")
    assert load_config(p)["effort"] == "low"      # env wins over the YAML default
    # Mapping is the contract: the level passes through verbatim, and no
    # token cap is set for any backend-verified level.
    for level in ("low", "medium", "high", "xhigh", "max"):
        assert get_reasoning_kwargs({"effort": level}) == {
            "reasoning_effort": level}
    assert "max_tokens" not in get_reasoning_kwargs({"effort": "low"})
    # An unknown level is not passed through: it lands on a defined level.
    assert get_reasoning_kwargs({"effort": "bogus"})["reasoning_effort"] \
        in EFFORT_RANK
    # The process-wide default is env-driven (test-supplied), never a pin.
    monkeypatch.setenv("EFFORT", "medium")
    reset_config()
    assert get_reasoning_kwargs({}) == {"reasoning_effort": "medium"}
    monkeypatch.delenv("EFFORT", raising=False)
    reset_config()
    # Per-agent override wins over the global effort.
    cfg = {"effort": "low", "effort_by_agent": {"hunter": "high",
                                                "validator": ""}}
    assert get_reasoning_kwargs(cfg, "hunter") == {"reasoning_effort": "high"}
    assert get_reasoning_kwargs(cfg, "validator") == {"reasoning_effort": "low"}
    assert get_reasoning_kwargs(cfg, "partitioner") == {"reasoning_effort": "low"}
    assert get_reasoning_kwargs(cfg, "bogus-agent") == {"reasoning_effort": "low"}


def test_concurrency_settings(tmp_path, monkeypatch):
    from cerberus.config import effective_config, reset_config

    monkeypatch.setenv("CONCURRENCY", "9")   # default supplied by the test
    reset_config()
    # The default is env-driven (test-supplied); no prod literal pinned.
    assert effective_config({})["concurrency"] == 9
    assert effective_config({"concurrency": 6})["concurrency"] == 6
    # Dict form: the ceilings are per-role; the effective value is their max.
    assert effective_config({"concurrency": {"hunters": 2, "validators": 7}})["concurrency"] == 7
    # Degenerate input never passes through: it lands on a positive int
    # (the normalizer's own fallback); oversized values pass through as
    # the operator asked (no artificial cap).
    fallback = effective_config({"concurrency": 0})["concurrency"]
    assert isinstance(fallback, int) and fallback != 0
    junk = effective_config({"concurrency": "bogus"})["concurrency"]
    assert junk == fallback
    assert effective_config({"concurrency": 99})["concurrency"] == 99
    monkeypatch.delenv("CONCURRENCY", raising=False)
    reset_config()


def test_effective_config_returns_the_active_cfg_for_empty_or_identical_input():
    from cerberus.config import effective_config, get_config, reset_config

    reset_config()
    cfg = get_config()
    assert effective_config() is cfg
    assert effective_config({}) is cfg
    assert effective_config(cfg) is cfg


def test_effective_config_ignores_malformed_section_overrides():
    from cerberus.config import effective_config, get_config, reset_config

    reset_config()
    active = get_config()
    for override in ({"sandbox": None}, {"partition": None},
                    {"verification": "broken"}):
        effective = effective_config(override)
        for section in ("sandbox", "partition", "verification"):
            assert isinstance(effective[section], dict)
        assert effective["sandbox"]["backend"] == active["sandbox"]["backend"]


def test_get_config_resolves_production_defaults_once(monkeypatch):
    import cerberus.config as config

    real_read_env = config._read_env
    calls = 0

    def read_env_once():
        nonlocal calls
        calls += 1
        return real_read_env()

    monkeypatch.setattr(config, "_read_env", read_env_once)
    monkeypatch.setattr(config, "_defaults", lambda *a, **k:
                        (_ for _ in ()).throw(AssertionError(
                            "get_config must not resolve defaults separately")))
    config.reset_config()
    assert config.get_config()["sandbox"]["backend"]
    assert calls == 1


def test_set_config_keeps_the_active_cfg_without_resolving_defaults(monkeypatch):
    import cerberus.config as config

    config.reset_config()
    active = config.get_config()
    monkeypatch.setattr(config, "_defaults", lambda *a, **k:
                        (_ for _ in ()).throw(AssertionError(
                            "installing the active cfg must not reload defaults")))
    assert config.set_config(active) is active


def test_set_config_does_not_replace_mapping_sections_with_scalars():
    from cerberus.config import get_config, reset_config, set_config

    reset_config()
    active = get_config()
    installed = set_config({"sandbox": None, "verification": "broken"})
    assert installed["sandbox"] == active["sandbox"]
    assert installed["verification"] == active["verification"]
