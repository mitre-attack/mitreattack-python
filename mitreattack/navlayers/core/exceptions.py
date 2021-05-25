UNSETVALUE = '(x)'


class BadInput(Exception):
    pass


class BadType(Exception):
    pass


class UninitializedLayer(Exception):
    pass


class UnknownLayerProperty(Exception):
    pass


class UnknownTechniqueProperty(Exception):
    pass


class MissingParameters(Exception):
    pass


def handler(caller, msg):
    """
        Prints a debug/warning/error message
        :param caller: the entity that called this function
        :param msg: the message to log
    """
    print('[{}] - {}'.format(caller, msg))


def typeChecker(caller, testee, desired_type, field):
    """
        Verifies that the tested object is of the correct type
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
        handler(caller, '{} [{}] is not a {}'.format(testee, field,
                                                     str(desired_type)))
        raise BadType


def typeCheckerArray(caller, testee, desired_type, field):
    """
        Verifies that the tested object is an array of the correct type
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
        handler(caller, '{} [{}] is not a {}'.format(testee, field, "Array"))
        raise BadType
    if not isinstance(testee[0], desired_type):
        handler(caller, '{} [{}] is not a {}'.format(testee, field, "Array of " + desired_type))
        raise BadType


def categoryChecker(caller, testee, valid, field):
    """
        Verifies that the tested object is one of a set of valid values
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
        handler(caller, '{} not a valid value for {}'.format(testee, field))
        raise BadInput


def loadChecker(caller, testee, required, field):
    """
        Verifies that the tested object contains all required fields
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
            handler(caller, '{} is not present in {} [{}]'.format(entry, field, testee))
            raise MissingParameters
