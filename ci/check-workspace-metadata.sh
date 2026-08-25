#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

metadata=$(cargo metadata --locked --no-deps --format-version 1)

jq --exit-status '
  (.packages[] | select(.name == "cageforge-backend-api")) as $reference
  | (.packages | map({key: .name, value: .version}) | from_entries) as $versions
  | all(.packages[];
      .repository == $reference.repository
      and .rust_version == $reference.rust_version
      and .readme != null)
  and ([.packages[] | select(.publish == []) | .name]
       == ["cageforge-upstream-review"])
  and all(.packages[];
      all(.dependencies[];
          if (.source == null and (.name | startswith("cageforge-")))
          then (.path != null and .req == ("^" + $versions[.name]))
          else true
          end))
' <<<"$metadata" >/dev/null
