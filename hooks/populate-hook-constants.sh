#!/bin/bash

# Look for the version string with additional handling for:
# - Abitrary Spaces: ` *`
# - Extracting the version into a match group: `(...)`
# - Substituting the matched string with the match group: `/\1/`
constantsVersion=$(sed -n 's/^ *VERSION *= *["]\([0-9\.]*\).*/\1/p' supertokens_python/constants.py)
setupVersion=$(sed -n 's/ *version *= *["]\([0-9\.]*\).*/\1/p' setup.py )

newestVersion=$( if [[ "$constantsVersion" > "$setupVersion" ]]; then echo "$constantsVersion"; else echo "$setupVersion"; fi )

currentBranch=$(git branch --show-current 2> /dev/null) || currentBranch="(unnamed branch)" # Get current branch
currentBranch=${currentBranch##refs/heads/}  # Remove refs/heads/ if present
