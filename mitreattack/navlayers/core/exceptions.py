"""Contains custom exceptions."""


UNSETVALUE = "(x)"


class BadInput(Exception):
    """Custom exception used for bad input."""

    pass


class BadType(Exception):
    """Custom exception used for bad types."""

    pass


class UninitializedLayer(Exception):
    """Custom exception used for uninitialized layers."""

    pass


class UnknownLayerProperty(Exception):
    """Custom exception used for unknown layer properties."""

    pass


class UnknownTechniqueProperty(Exception):
    """Custom exception used for unknown technique properties."""

    pass


class MissingParameters(Exception):
    """Custom exception used for missing parameters."""

    pass


def handler(caller, msg):
    """Print a debug/warning/error message.

    :param caller: the entity that called this function
    :param msg: the message to log
    """
    print(f"[{caller}] - {msg}")


def typeChecker(caller, testee, desired_type, field):
    """Verify that the tested object is of the correct type.

    :param caller: the entity that called this function (used for error
        messages)
    :param testee: the element to test
    :param desired_type: the type the element should be
    :param field: what the element is to be used as (used for error
        messages)
    :raises BadType: error denoting the testee element is not of the
        correct type
    """
    if not isinstance(testee, desired_type):
        handler(caller, f"{testee} [{field}] is not a {str(desired_type)}")
        raise BadType


def typeCheckerArray(caller, testee, desired_type, field):
    """Verify that the tested object is an array of the correct type.

    :param caller: the entity that called this function (used for error
        messages)
    :param testee: the element to test
    :param desired_type: the type the element should be
    :param field: what the element is to be used as (used for error
        messages)
    :raises BadType: error denoting the testee element is not of the
        correct type
    """
    if not isinstance(testee, list):
        handler(caller, f"{testee} [{field}] is not a Array")
        raise BadType
    if not isinstance(testee[0], desired_type):
        handler(caller, f"{testee} [{field}] is not a {'Array of ' + desired_type}")
        raise BadType


def categoryChecker(caller, testee, valid, field):
    """Verify that the tested object is one of a set of valid values.

    :param caller: the entity that called this function (used for error
        messages)
    :param testee: the element to test
    :param valid: a list of valid values for the testee
    :param field: what the element is to be used as (used for error
        messages)
    :raises BadInput: error denoting the testee element is not one of
        the valid options
    """
    if testee not in valid:
        handler(caller, f"{testee} not a valid value for {field}")
        raise BadInput


def loadChecker(caller, testee, required, field):
    """Verify that the tested object contains all required fields.

    :param caller: the entity that called this function (used for error
        messages)
    :param testee: the element to test
    :param required: a list of required values for the testee
    :param field: what the element is to be used as (used for error
        messages)
    :raises BadInput: error denoting the testee element is not one of
        the valid options
    """
    for entry in required:
        if entry not in testee:
            handler(caller, f"{entry} is not present in {field} [{testee}]")
            raise MissingParameters
