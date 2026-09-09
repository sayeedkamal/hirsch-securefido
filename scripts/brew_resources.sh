#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Regenerate the Homebrew formula's resource stanzas and sdist sha256.
#
# Run on macOS after publishing a release to PyPI:
#     ./scripts/brew_resources.sh 1.0.0
#
# Requires: brew, and `brew install pipgrip` for resource generation.
# ---------------------------------------------------------------------------
set -euo pipefail

VERSION="${1:-1.0.0}"
PACKAGE="hirsch-securefido"
FORMULA="$(dirname "$0")/../Formula/hirsch-securefido.rb"

if ! command -v brew >/dev/null 2>&1; then
  echo "error: Homebrew is required (this script runs on macOS)." >&2
  exit 1
fi

if ! brew list pipgrip >/dev/null 2>&1; then
  echo "==> Installing pipgrip (needed to resolve resource blocks)"
  brew install pipgrip
fi

echo "==> Fetching sdist checksum for ${PACKAGE} ${VERSION}"
SDIST_URL="https://pypi.org/pypi/${PACKAGE}/${VERSION}/json"
SDIST_SHA=$(
  curl -fsSL "$SDIST_URL" |
    python3 -c "import json,sys; d=json.load(sys.stdin); print(next(u['digests']['sha256'] for u in d['urls'] if u['packagetype']=='sdist'))"
)
echo "    sha256 = ${SDIST_SHA}"

echo "==> Generating resource stanzas"
brew update-python-resources --print-only "$FORMULA" 2>/dev/null ||
  echo "    (run 'brew update-python-resources ${FORMULA}' once the formula is tapped)"

echo
echo "Next steps:"
echo "  1. Replace REPLACE_WITH_SDIST_SHA256 in ${FORMULA} with:"
echo "       ${SDIST_SHA}"
echo "  2. Paste the regenerated resource blocks over the existing ones."
echo "  3. Validate:"
echo "       brew install --build-from-source ${FORMULA}"
echo "       brew test ${PACKAGE}"
echo "       brew audit --strict --new ${PACKAGE}"
