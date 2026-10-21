#!/bin/bash

# Look for the version string with additional handling for:
# - Abitrary Spaces: ` *`
# - Extracting the version into a match group: `(...)`
# - Substituting the matched string with the match group: `/\1/`
export constantsVersion=$(sed -n 's/^ *VERSION *= *["]\([0-9\.]*\).*/\1/p' supertokens_python/constants.py)
export constantsVersionXy=$(sed -n 's/^ *VERSION *= *["]\([0-9]*\.[0-9]*\).*/\1/p' supertokens_python/constants.py)
export setupVersion=$(sed -n 's/ *version *= *["]\([0-9\.]*\).*/\1/p' setup.py )
export setupVersionXy=$(sed -n 's/ *version *= *["]\([0-9]*\.[0-9]*\).*/\1/p' setup.py )

# --- Shared version-hook contract (supertokens/actions release-tag.yml) ---
# The reusable release pipeline sources this script and reads constantsVersion /
# constantsVersionXy (which python already exports above). Repo-specific setup
# checks also belong here and exit non-zero to fail the pipeline's setup job.
#
# constants.py VERSION and setup.py version must stay in lockstep; a mismatch
# means a botched bump, so refuse to tag/release. (Previously enforced inline in
# the "Check tag and branch correctness" step of the release pipeline; also
# checked by hooks/check-version.sh at pre-commit and check-docs.yml on version
# branches.)
if [[ "$constantsVersion" != "$setupVersion" ]]; then
    echo "Constants version ($constantsVersion) and setup version ($setupVersion) do not match." >&2
    exit 1
fi

export newestVersion=$( if [[ "$constantsVersion" > "$setupVersion" ]]; then echo "$constantsVersion"; else echo "$setupVersion"; fi )

# Target branch of the PR.
# Ideally, this is all we want to check.
if [[ "$GITHUB_BASE_REF" != "" ]]
then
    export targetBranch="$GITHUB_BASE_REF"
else # Fallback to current branch if not in a PR
    export targetBranch=$(git branch --show-current 2> /dev/null) || export targetBranch="(unnamed branch)" # Get current branch
fi
export targetBranch=${targetBranch##refs/heads/}  # Remove refs/heads/ if present
