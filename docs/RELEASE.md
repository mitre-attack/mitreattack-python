# Release Process

In order to release a new version of mitreattack-python, follow the process outlined here:

1. Verify that all changes desired in the next release are present in the `master` branch.
2. Verify that all changes are documented in the CHANGELOG staged in the `master` branch.
3. Build the _mitreattack-python_ package from source and install it locally:
   1. [Optional] Activate a virtualenv. e.g., `source ./venv/bin/activate`
   2. Uninstall any older/previously installed versions of mitreattack-python: `pip uninstall mitreattack-python`
   3. If you have previously built from source, remove older build artifacts: `rm -rf dist/`. 
   4. Build the package: `python setup.py sdist bdist_wheel`.
   5. Lint the wheel contents with [check-wheel-contents](https://github.com/jwodder/check-wheel-contents): `check-wheel-contents dist/`
   6. Install the package locally using pip, and import it in a python session to validate the build: `pip install --find-links=./dist mitreattack-python`

4. Run the test suite in `/tests/` with pytest.

   ```bash
   # must run from the tests/ directory
   cd tests/
   pytest --cov=mitreattack --cov-report html
   ```

5. Edit `setup.py` and increment the version number.
   Update other fields in setup.py as necessary (used libraries, etc.)
6. Commit any uncommitted changes.
7. Tag the release:
   1. Tag the `master` branch with the version number - `git tag -a "vA.B.C" -m "mitreattack-python version A.B.C"`
   2. Push both the commit and the tag - `git push`/`git push --tags`
8. Verify that the package uploaded correctly
   1. Check that GitHub Actions succeeded: <https://github.com/mitre-attack/mitreattack-python/actions>
   2. Verify PyPI has expected release: <https://pypi.org/project/mitreattack-python/>
