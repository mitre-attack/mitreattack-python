# Release Process

In order to release a new version of mitreattack-python, follow the process outlined here:

1. Verify that all changes desired in the next release are present in the `master` branch.
2. Verify that all changes are documented in the CHANGELOG staged in the `master` branch.
3. Run the test suite in `/tests/` with pytest.
   Please note, this takes a while to run, up to several hours.

   ```bash
   # run from the tests/ directory
   PYTHONPATH=. pytest --cov=mitreattack --cov-report html
   ```

4. Edit setup.py and increment the version number.
   Update other fields in setup.py as necessary (used libraries, etc.)
   1. Update setuptools and wheel - `pip install --upgrade setuptools wheel`.
5. [Optional, but recommended] Build the python library for pip locally:
   1. Remove older built pacakges - `rm -rf dist/`.
   2. Build the package - `python setup.py sdist bdist_wheel`.
   3. Lint the wheel contents with [check-wheel-contents](https://github.com/jwodder/check-wheel-contents) - `check-wheel-contents dist/`
   4. Install the package locally using pip, and import it in a python session to validate the build.
6. Tag the release:
   1. Tag the `master` branch with the version number - `git tag -a "vA.B.C" -m "mitreattack-python version A.B.C"`
   2. Push both the commit and the tag - `git push`/`git push --tags`
7. Verify that the package uploaded correctly
   1. Check that GitHub Actions succeeded: <https://github.com/mitre-attack/mitreattack-python/actions>
   2. Verify PyPI has expected release: <https://pypi.org/project/mitreattack-python/>
