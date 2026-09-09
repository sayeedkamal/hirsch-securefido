# Publishing

Release checklist for `hirsch-securefido`.

## 1. Pre-flight

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -q
python -m build
twine check dist/*
```

Confirm the version in `pyproject.toml` and `src/hirsch_securefido/__init__.py`
match, and that `CHANGELOG` / README reflect the release.

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

The formula lives in `Formula/hirsch-securefido.rb` and must be copied into the
tap repository `hirschsecure/homebrew-tap`.

After the PyPI release is live:

```bash
./scripts/brew_resources.sh 1.0.0
```

That prints the sdist `sha256`. Update the formula's `url` and `sha256`, refresh
the `resource` blocks, then validate on macOS:

```bash
brew install --build-from-source Formula/hirsch-securefido.rb
brew test hirsch-securefido
brew audit --strict --new hirsch-securefido
```

Commit the formula to the tap:

```bash
cd homebrew-tap
cp ../hirsch-securefido/Formula/hirsch-securefido.rb Formula/
git commit -am "hirsch-securefido 1.0.0"
git push
```

Users then install with:

```bash
brew tap hirschsecure/tap
brew install hirsch-securefido
```

## 4. Post-release

```bash
brew uninstall hirsch-securefido && brew install hirschsecure/tap/hirsch-securefido
hirsch-securefido info    # with a real Hirsch key attached
```

Hardware paths that CI cannot cover must be checked by hand once per release:

- [ ] `info` against a real Hirsch SecureKey over USB HID
- [ ] `set-pin` on a factory-fresh token
- [ ] `change-pin` with correct and incorrect current PINs
- [ ] `reset` including the re-insert window and the touch prompt
