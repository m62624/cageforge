#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

python_workflow=.github/workflows/python-release.yml
release_workflow=.github/workflows/release.yml

# The wheel audit is a heredoc script. The '-' is significant: without it,
# Python treats the first wheel archive as the script and never runs the audit.
grep -F -- 'python - "${wheels[@]}" "${{ matrix.resource }}" <<'"'"'PY'"'"'' "$python_workflow" >/dev/null
if grep -F -- 'python "${wheels[@]}"' "$python_workflow" >/dev/null; then
    echo "python wheel audit is missing the stdin script marker" >&2
    exit 1
fi

# Keep the first PyPI release on the deliberate bootstrap gate, while proving
# that its authentication is keyless and its package directory is complete.
publish_block="$(awk '
    /^  publish-python:/ { inside=1; print; next }
    inside && /^  [[:alnum:]_-]+:/ { exit }
    inside { print }
' "$release_workflow")"
grep -F -- 'id-token: write' <<<"$publish_block" >/dev/null
grep -F -- 'pypa/gh-action-pypi-publish@release/v1' <<<"$publish_block" >/dev/null
grep -F -- 'packages-dir: dist' <<<"$publish_block" >/dev/null
grep -F -- 'skip-existing: true' <<<"$publish_block" >/dev/null
grep -F -- 'needs: [prepare, tag, python]' <<<"$publish_block" >/dev/null

# Local Gradle builds and the JVM smoke consumer must follow the workspace
# version; a stale 0.2.x fallback would publish or consume the wrong artifact.
if grep -F -- 'orElse("0.2.0")' \
    crates/bindings/cageforge-java/jvm/build.gradle.kts \
    crates/bindings/cageforge-java/jvm/smoke/build.gradle.kts >/dev/null; then
    echo "JVM build scripts contain a stale 0.2.0 fallback" >&2
    exit 1
fi
