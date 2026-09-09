# Publishing to Homebrew

How to get `brew install hirsch-securefido` working on macOS.

## The ordering constraint

Homebrew does not host code. The formula points at a **PyPI sdist** and builds
from it, so the order is fixed:

```
1. publish to PyPI   ->   2. get the sdist sha256   ->   3. update the formula   ->   4. push the tap
```

Step 3 cannot happen first. Until the version exists on PyPI there is nothing
to checksum, which is why `Formula/hirsch-securefido.rb` currently carries
`REPLACE_WITH_SDIST_SHA256`.

## Which distribution channel?

| | Formula (`brew install`) | Cask (`brew install --cask`) |
| --- | --- | --- |
| For | CLI tools built from source | prebuilt `.app` bundles, binaries |
| Ours | **yes** | no |

This is a command-line tool, so it is a **formula**. A cask would only apply if
you later ship a `.app`, which would additionally need codesigning and
notarization.

## Which tap?

**Your own tap** (`hirschsecure/homebrew-tap`) is the right choice here:

- You control releases; no third-party review queue.
- homebrew-core requires notability (roughly 30+ GitHub stars, 30+ forks, or
  equivalent usage) and rejects vendor-specific hardware tools that only work
  with one company's device. This tool is gated to Hirsch VID `04E6`, so it
  would very likely be declined.

Users then run:

```bash
brew tap hirschsecure/tap
brew install hirsch-securefido
```

`brew tap hirschsecure/tap` resolves to `github.com/hirschsecure/homebrew-tap`.
The `homebrew-` prefix on the repo name is required; the tap name drops it.

---

## Step 1 - Publish to PyPI

One-time: register the project name and configure Trusted Publishing at
<https://pypi.org/manage/account/publishing/>

| Field | Value |
| --- | --- |
| PyPI project | `hirsch-securefido` |
| Owner | `hirschsecure` |
| Repository | `hirsch-securefido` |
| Workflow | `publish.yml` |
| Environment | `pypi` |

Then release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The `Publish` workflow verifies the tag matches `pyproject.toml`, builds, and
uploads with no stored API token. Confirm it worked:

```bash
pip download --no-deps --no-binary :all: hirsch-securefido==1.0.0
```

### Manual alternative

```bash
python -m build
twine upload --repository testpypi dist/*   # rehearse
twine upload dist/*
```

## Step 2 - Create the tap repository

Once, on GitHub: create a **public** repo named `homebrew-tap` under the
`hirschsecure` org.

```bash
git clone https://github.com/hirschsecure/homebrew-tap
cd homebrew-tap
mkdir -p Formula
```

The `Formula/` subdirectory name matters; Homebrew looks there.

## Step 3 - Update the formula for the release

On macOS, from this repository:

```bash
./scripts/brew_release.sh 1.0.0
```

That script:

1. confirms `1.0.0` is actually on PyPI, and stops if not
2. rewrites the formula's `url` and `sha256` from the real sdist
3. regenerates the Python `resource` blocks via `brew update-python-resources`
4. runs `ruby -c` and `brew style`

It edits **only** the formula's own url/sha256; the four vendored resource
digests are left untouched.

## Step 4 - Validate locally before publishing

Do not skip this. It is the first time the formula is genuinely exercised.

```bash
brew install --build-from-source Formula/hirsch-securefido.rb
brew test hirsch-securefido
brew audit --strict --new hirsch-securefido
```

- `install` proves the virtualenv builds and every resource resolves. Expect a
  few minutes: `cryptography` compiles Rust extensions from source.
- `test` runs the formula's test block: `--version`, the four commands in
  `--help`, and the exit-2 no-device contract.
- `audit --strict --new` applies the rules a new formula must satisfy.

Then confirm it behaves with hardware attached:

```bash
hirsch-securefido            # interactive menu
hirsch-securefido info       # must work WITHOUT sudo
```

## Step 5 - Push the tap

```bash
cp Formula/hirsch-securefido.rb ../homebrew-tap/Formula/
cd ../homebrew-tap
git add Formula/hirsch-securefido.rb
git commit -m "hirsch-securefido 1.0.0"
git push
```

Verify as a user would, from a clean state:

```bash
brew untap hirschsecure/tap 2>/dev/null || true
brew tap hirschsecure/tap
brew install hirsch-securefido
hirsch-securefido --version
```

## Subsequent releases

```bash
# 1. bump the version in pyproject.toml AND src/hirsch_securefido/__init__.py
#    (tests/test_packaging.py fails if they disagree)
git tag v1.1.0 && git push origin v1.1.0     # publishes to PyPI

# 2. refresh and validate the formula
./scripts/brew_release.sh 1.1.0
brew install --build-from-source Formula/hirsch-securefido.rb
brew test hirsch-securefido

# 3. ship it
cp Formula/hirsch-securefido.rb ../homebrew-tap/Formula/
cd ../homebrew-tap && git commit -am "hirsch-securefido 1.1.0" && git push
```

Users upgrade with `brew update && brew upgrade hirsch-securefido`.

## Troubleshooting

**`SHA256 mismatch`** - the formula's checksum does not match what PyPI served.
Re-run `./scripts/brew_release.sh <version>`. Never edit a digest by hand.

**`Could not find a version that satisfies the requirement`** - a transitive
dependency lacks a `resource` block. Re-run `brew update-python-resources`.

**`cryptography` fails to build** - the Rust toolchain is missing. The formula
declares `depends_on "rust" => :build`; confirm `brew install rust` succeeds.

**`Error: Formula is not in the tap`** - the file must be at
`Formula/hirsch-securefido.rb`, and the class name `HirschSecurefido` must match
the filename. `tests/test_formula.py` checks that pairing.

**`No such keg`** on `brew test` - install before testing.

## What is verified, and what is not

Automated in CI (`.github/workflows/ci.yml`, `formula` job on macOS):
`ruby -c` parses the formula, and `brew style` audits it.

Also checked offline by `tests/test_formula.py`: block balance, required
fields, audit-sensitive `desc` style, version agreement, full-length resource
digests, and that the test block asserts real behavior. Resource URLs are
confirmed reachable on PyPI over the network.

**Not verified here**, because this repo has no macOS host, no Ruby, and no
Hirsch key: `brew install`, `brew test`, `brew audit`, and every USB HID path.
Step 4 is the first time those run. Treat it as required, not optional.
