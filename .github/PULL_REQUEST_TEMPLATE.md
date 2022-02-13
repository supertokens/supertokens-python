## Summary of change

(A few sentences about this PR)

## Related issues

-   Link to issue1 here
-   Link to issue1 here

## Test Plan

(Write your test plan here. If you changed any code, please provide us with clear instructions on how you verified your changes work. Bonus points for screenshots and videos!)

## Documentation changes

(If relevant, please create a PR in our [docs repo](https://github.com/supertokens/docs), or create a checklist here highlighting the necessary changes)

## Checklist for important updates

-   [ ] Changelog has been updated
-   [ ] `coreDriverInterfaceSupported.json` file has been updated (if needed)
    -   Along with the associated array in `supertokens_python/constants.py`
-   [ ] `frontendDriverInterfaceSupported.json` file has been updated (if needed)
-   [ ] Changes to the version if needed
    -   In `setup.py`
    -   In `supertokens_python/constants.py`
-   [ ] Had installed and ran the pre-commit hook
-   [ ] Issue this PR against the latest non released version branch.
    -   To know which one it is, run find the latest released tag (`git tag`) in the format `vX.Y.Z`, and then find the latest branch (`git branch --all`) whose `X.Y` is greater than the latest released tag.
    -   If no such branch exists, then create one from the latest released branch.
-   [ ] If have added a new web framework, update the `supertokens_python/utils.py` file to include that in the `FRAMEWORKS` variable
-   [ ] If added a new recipe that has a User type with extra info, then be sure to change the User type in supertokens_python/types.py
 
## Remaining TODOs for this PR

-   [ ] Item1
-   [ ] Item2