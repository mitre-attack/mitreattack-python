# Release Process

In order to release a new version of mitreattack-python, follow the process outlined here:

1. Verify that all changes desired in the next release are present in the `develop` branch (unless this is an urgent bug fix, in which case more nuanced approaches may be necessary).
2. Verify that all changes are documented in the CHANGELOG staged in the `develop` branch.
3. Run validation testing on the library, specifically the pytest collection located in `tests/`. Please note, this test battery is exhaustive and takes a while to run (just under 3 hours at time of writing).
4. Build the python library for pip:
   1. Edit setup.py and increment the version number. Update other fields in setup.py as necessary (used libraries, etc.)
   2. Update setuptools and wheel - `python3 -m pip install --user --upgrade setuptools wheel`.
   3. Build the package - `python3 setup.py sdist bdist_wheel`.
   4. Install the package locally using pip, and import it in a python session to validate the build.
   5. Upload the build to PyPI - `twine upload --repository pypi dist/*`.
5. Update the Github repository with the new release:
   1. Merge `develop` (or other branch) into `master`.
   2. Tag the merge commit with the version number - `git tag -a "vA.B.C" -m "mitreattack-python version A.B.C"`
   3. Push both the merge commit and the tag - `git push`/`git push --tags`
   4. Publish a release on from the web GUI. Tag the release with the appropriate tag, and reference the changelog for more details in the description of the release.
