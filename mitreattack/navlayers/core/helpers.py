"""Helper functions."""


def handle_object_placement(handle_to_self_field, potential_object, objectType, list=False):
    """Check to see if we can safely set a given field (handle_to_self_field) to a potential_object by checking whether or not it is an instance of objectType.

    :param handle_to_self_field: the field the object is to be assigned to
    :param potential_object: the potential instance of an object
    :param objectType: the type of object being looked for
    :param list: whether or not handle_to_self_field should be a list
    :return: properly referencable object, or False if the object wasn't of the expected type
    """
    if isinstance(potential_object, objectType):
        if list:
            handle_to_self_field.append(potential_object)
        else:
            handle_to_self_field = potential_object
        return handle_to_self_field
    return False
