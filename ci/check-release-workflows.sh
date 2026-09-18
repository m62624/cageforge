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

# Keep PyPI keyless and verify that every registry publication shares the
# complete tested-artifact gate instead of waiting on another registry.
publish_block="$(awk '
    /^  publish-python:/ { inside=1; print; next }
    inside && /^  [[:alnum:]_-]+:/ { exit }
    inside { print }
' "$release_workflow")"
grep -F -- 'id-token: write' <<<"$publish_block" >/dev/null
grep -F -- 'pypa/gh-action-pypi-publish@release/v1' <<<"$publish_block" >/dev/null
grep -F -- 'packages-dir: dist' <<<"$publish_block" >/dev/null
grep -F -- 'skip-existing: true' <<<"$publish_block" >/dev/null

registry_needs='needs: [prepare, tests, dist, jvm, python]'
for job in publish-jvm publish-python publish-crates; do
    block="$(awk -v job="$job" '
        $0 == "  " job ":" { inside=1; print; next }
        inside && /^  [[:alnum:]_-]+:/ { exit }
        inside { print }
    ' "$release_workflow")"
    grep -F -- "$registry_needs" <<<"$block" >/dev/null
    needs_line="$(grep -F -- 'needs:' <<<"$block")"
    if grep -Eq 'publish-(jvm|python|crates)' <<<"$needs_line"; then
        echo "$job must not wait for another registry publication" >&2
        exit 1
    fi
done

# Local Gradle builds and the JVM smoke consumer must follow the workspace
# version; a stale 0.2.x fallback would publish or consume the wrong artifact.
if grep -F -- 'orElse("0.2.0")' \
    crates/bindings/cageforge-java/jvm/build.gradle.kts \
    crates/bindings/cageforge-java/jvm/smoke/build.gradle.kts >/dev/null; then
    echo "JVM build scripts contain a stale 0.2.0 fallback" >&2
    exit 1
fi
