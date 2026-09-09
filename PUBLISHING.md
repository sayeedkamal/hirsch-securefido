# Publishing

Release checklist for `hirsch-securefido`.

## 1. Pre-flight

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -q
python scripts/mutation_check.py    # suite must detect all injected bugs
python -m build
twine check dist/*
```

Confirm the version in `pyproject.toml` and `src/hirsch_securefido/__init__.py`
match, and that `CHANGELOG` / README reflect the release. `tests/test_packaging.py`
and `tests/test_formula.py` enforce that agreement automatically.

## 2. PyPI

### Automated (recommended)

The `Publish` workflow uses PyPI **Trusted Publishing** (OIDC), so no API token
is stored in the repository.

One-time setup at
<https://pypi.org/manage/project/hirsch-securefido/settings/publishing/>:

| Field | Value |
| --- | --- |
| Owner | `hirschsecure` |
| Repository | `hirsch-securefido` |
| Workflow | `publish.yml` |
| Environment | `pypi` |

Then release by tagging:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow refuses to publish if the tag does not match the packaged version.

### Manual

```bash
python -m build
twine upload --repository testpypi dist/*   # rehearse first
twine upload dist/*
```

Verify the published artifact installs cleanly:

```bash
python -m venv /tmp/verify && /tmp/verify/bin/pip install hirsch-securefido
/tmp/verify/bin/hirsch-securefido --version
```

## 3. Homebrew

See **[HOMEBREW.md](HOMEBREW.md)** for the full walkthrough: tap setup,
formula-vs-cask, local validation, and troubleshooting.

Short version, after the PyPI release is live:

```bash
./scripts/brew_release.sh 1.0.0          # rewrites url + sha256, refreshes resources
brew install --build-from-source Formula/hirsch-securefido.rb
brew test hirsch-securefido
brew audit --strict --new hirsch-securefido
```

Then publish to the tap:

```bash
cp Formula/hirsch-securefido.rb ../homebrew-tap/Formula/
cd ../homebrew-tap && git commit -am "hirsch-securefido 1.0.0" && git push
```

Users install with:

```bash
brew tap hirschsecure/tap
brew install hirsch-securefido
```

## 4. Post-release

```bash
brew uninstall hirsch-securefido && brew install hirschsecure/tap/hirsch-securefido
hirsch-securefido info    # with a real Hirsch key attached
```

## Manual hardware verification

Everything below is **outside** what the automated suite can reach. The tests
use a virtual authenticator that speaks real CTAP2 CBOR, so protocol logic is
covered, but USB HID transport, the reset power-up window, and the physical
touch have no software equivalent.

Run this once per release on macOS with a real Hirsch SecureKey:

- [ ] `hirsch-securefido list` shows the key over USB HID
- [ ] `hirsch-securefido info` reports the true AAGUID and firmware version
- [ ] `info` runs **without `sudo`** (the core macOS port claim)
- [ ] `set-pin` on a factory-fresh token
- [ ] `change-pin` with the correct current PIN
- [ ] `change-pin` with a wrong PIN decrements the retry counter shown by `info`
- [ ] `reset` refused when run outside the power-up window
- [ ] `reset` succeeds when the token is re-inserted, and the touch prompt appears
- [ ] `reset` cancelled by declining the touch, leaving credentials intact
- [ ] After a successful `reset`, `info` reports `PIN Set: No`
- [ ] NFC path with `pip install pyscard` and a card on a reader, if in scope

Record the macOS version, the key's firmware version, and the fido2 version
used, so a regression can be attributed later.
