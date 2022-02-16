# Contributors

## Reporting Issues
If you encounter an issue with the `mitreattack-python` library, please let us know by filing a [Github issue](https://github.com/mitre-attack/mitreattack-python/issues). When doing so, please make sure you provide the following information:
* Describe (in detail as possible) what occurred and what you were expecting to occur. Any information you can provide, such stack traces or errors are very helpful.
* Describe the steps necessary to replicate the issue.
* Indicate your OS and python versions.

## Suggested New Features
If you have an idea for a new feature for `mitreattack-python`, please let us know by filing a [Github issue](https://github.com/mitre-attack/mitreattack-python/issues). When doing so, please make sure you provide the following information:
* Explain the functionality you are proposing, and its use case - what would it be useful for or allow you to do?
* List what existing ATT&CK tools or resources map to the proposed functionality
* If applicable, provide examples of other requests for the proposed functionality

## Developing
If you want to work on the `mitreattack-python` library and contribute to its ongoing development, we welcome merge requests! You can set up an environment for development by following this process:
1. Clone the repository - `git clone https://github.com/mitre-attack/mitreattack-python`.
2. Create a virtual environment, and activate it - `python3 -m venv venv`/`. venv/bin/activate`.
3. Install the appropriate python modules via pip - `pip install -r requirements-dev.txt`.

### Merge Requests
When making a merge request, please make sure to include a summary of what the changes are intended to do, functionality wise, and the testing performed to validate the changes (ideally in the form of new pytests integrated into the `tests/` collection, though this is not strictly required). In addition, the complete pytest test battery `tests/` must be passed without errors in order for any code to actually be merged. 