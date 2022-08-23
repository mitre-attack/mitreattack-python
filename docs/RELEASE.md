# Release Process

In order to release a new version of mitreattack-python, follow the process outlined here:

1. Verify that all changes desired in the next release are present in the `master` branch.
2. Verify that all changes are documented in the CHANGELOG staged in the `master` branch.
3. Run validation testing on the library with pytest.
   Please note, the test suite takes a while to run, up to several hours.

   ```bash
   # run from root of git repo
   PYTHONPATH=. pytest --cov=mitreattack --cov-report html
   ```

4. Build the python library for pip:
   1. Edit setup.py and increment the version number. Update other fields in setup.py as necessary (used libraries, etc.)
   2. Update setuptools and wheel - `pip install --upgrade setuptools wheel`.
   3. Build the package - `python setup.py sdist bdist_wheel`.
   4. Install the package locally using pip, and import it in a python session to validate the build.
   5. Upload the build to PyPI - `twine upload --repository pypi dist/*`.
5. Update the Github repository with the new release:
   1. Tag the releasable commit with the version number - `git tag -a "vA.B.C" -m "mitreattack-python version A.B.C"`
   2. Push both the commit and the tag - `git push`/`git push --tags`
