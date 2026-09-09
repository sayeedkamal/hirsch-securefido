#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Update the Homebrew formula for a published release.
#
#     ./scripts/brew_release.sh 1.0.0
#
# Rewrites the formula's top-level url + sha256 from the real PyPI sdist, then
# regenerates the Python `resource` stanzas. Run on macOS AFTER the version is
# live on PyPI: Homebrew downloads from PyPI, so the release must exist first.
#
# Requires: Homebrew. Installs pipgrip on demand for resource resolution.
# ---------------------------------------------------------------------------
set -euo pipefail

VERSION="${1:-}"
PACKAGE="hirsch-securefido"
HERE="$(cd "$(dirname "$0")" && pwd)"
FORMULA="${HERE}/../Formula/hirsch-securefido.rb"

if [[ -z "$VERSION" ]]; then
  echo "usage: $0 <version>   e.g. $0 1.0.0" >&2
  exit 2
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "error: Homebrew is required; run this on macOS." >&2
  exit 1
fi

if [[ ! -f "$FORMULA" ]]; then
  echo "error: formula not found at $FORMULA" >&2
  exit 1
fi

echo "==> Confirming ${PACKAGE} ${VERSION} is on PyPI"
META=$(curl -fsSL "https://pypi.org/pypi/${PACKAGE}/${VERSION}/json") || {
  echo "error: ${PACKAGE} ${VERSION} is not on PyPI yet." >&2
  echo "       Publish to PyPI first; Homebrew builds from that sdist." >&2
  exit 1
}

read -r SDIST_URL SDIST_SHA <<<"$(
  printf '%s' "$META" | python3 -c '
import json, sys
data = json.load(sys.stdin)
sdists = [u for u in data["urls"] if u["packagetype"] == "sdist"]
if not sdists:
    sys.exit("error: no sdist found; Homebrew needs one (python -m build)")
u = sdists[0]
print(u["url"], u["digests"]["sha256"])
'
)"

echo "    url    ${SDIST_URL}"
echo "    sha256 ${SDIST_SHA}"

echo "==> Rewriting the formula url and sha256"
python3 - "$FORMULA" "$SDIST_URL" "$SDIST_SHA" <<'PY'
import re
import sys

path, url, sha = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as fh:
    text = fh.read()

# Only the first url/sha256 pair is the formula's own source; the rest
# belong to resource blocks and must not be touched.
text, n_url = re.subn(r'^(\s*)url\s+"[^"]+"', rf'\1url "{url}"', text, count=1, flags=re.M)
text, n_sha = re.subn(r'^(\s*)sha256\s+"[^"]+"', rf'\1sha256 "{sha}"', text, count=1, flags=re.M)
if not (n_url and n_sha):
    sys.exit("error: could not locate the formula's url/sha256 fields")

with open(path, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(text)
print("    formula updated")
PY

if ! brew list pipgrip >/dev/null 2>&1; then
  echo "==> Installing pipgrip (resolves transitive Python resources)"
  brew install pipgrip
fi

echo "==> Regenerating resource stanzas"
brew update-python-resources "$FORMULA" || {
  echo "warning: automatic resource update failed; check the blocks by hand" >&2
}

echo "==> Validating"
ruby -c "$FORMULA" >/dev/null && echo "    ruby syntax ok"
brew style "$FORMULA" || echo "warning: brew style reported issues"

cat <<EOF

Formula updated for ${VERSION}. Next:

  brew install --build-from-source ${FORMULA}
  brew test ${PACKAGE}
  brew audit --strict --new ${PACKAGE}

Then copy it into the tap and push:

  cp ${FORMULA} ../homebrew-tap/Formula/
  cd ../homebrew-tap && git commit -am "${PACKAGE} ${VERSION}" && git push
EOF
