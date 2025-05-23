#!/bin/bash

# Look for the version string with additional handling for:
# - Abitrary Spaces: ` *`
# - Extracting the version into a match group: `(...)`
# - Substituting the matched string with the match group: `/\1/`
export constantsVersion=$(sed -n 's/^ *VERSION *= *["]\([0-9\.]*\).*/\1/p' supertokens_python/constants.py)
export constantsVersionXy=$(sed -n 's/^ *VERSION *= *["]\([0-9]*\.[0-9]*\).*/\1/p' supertokens_python/constants.py)
export setupVersion=$(sed -n 's/ *version *= *["]\([0-9\.]*\).*/\1/p' setup.py )
export setupVersionXy=$(sed -n 's/ *version *= *["]\([0-9]*\.[0-9]*\).*/\1/p' setup.py )

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
