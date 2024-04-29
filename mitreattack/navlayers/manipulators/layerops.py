"""Contains LayerOps class."""

# Example Use:
# from navlayers.manipulators.layerops import LayerOps
# from navlayers.core.layer import Layer

# demo = Layer()
# demo.load_file("C:\Users\attack\Downloads\layer.json")
# demo2 = Layer()
# demo2.load_input(Existing_Layer_String_Previously_Loaded)

# lo = LayerOps(score=lambda x: x[0] * x[1], name=lambda x: x[1],
#               desc=lambda x: "This is an list example")
# out_layer = lo.process([demo, demo2])
# out_layer.export_file("C:\demo_layer1.json")

# lo2 = LayerOps(score=lambda x: x['a'], color=lambda x: x['b'],
#                desc=lambda x: "This is a dict example")
# out_layer2 = lo2.process({'a': demo, 'b': demo2})
# dict_layer = out_layer2.get_dict()
# print(dict_layer)
# out_layer2.export_file("C:\demo_layer2.json")

import copy
from mitreattack.navlayers.core import Layer


class InvalidFormat(Exception):
    """Custom exception used for invalid formats."""

    pass


class BadLambda(Exception):
    """Custom exception used for bad lambdas."""

    pass


class MismatchedDomain(Exception):
    """Custom exception used for mismatched domains."""

    pass


class LayerOps:
    """A LayerOps object."""

    def __init__(
        self,
        score=None,
        comment=None,
        enabled=None,
        colors=None,
        metadata=None,
        name=None,
        desc=None,
        default_values=None,
    ):
        """Initialize - configures the object to handle processing based on user provided Lambdas.

        :param score: lambda to calculate score
        :param comment: lambda to generate comments
        :param enabled: lambda to determine enabled status
        :param metadata: lambda to generate metadata
        :param name: new name to apply to the resulting layer
        :param desc: new description to apply to the resulting layer
        :param default_values: dictionary containing desired default
            values for missing data element values
        """
        self._score = score
        self._comment = comment
        self._enabled = enabled
        self._colors = colors
        self._metadata = metadata
        self._name = name
        self._desc = desc
        self._default_values = {"comment": "", "enabled": True, "color": "#ffffff", "score": 1, "metadata": []}
        if default_values is not None:
            for entry in default_values:
                self._default_values[entry] = default_values[entry]

    def process(self, data, default_values=None):
        """Take a list or dict of Layer objects, and processes them.

        :param data: A dict or list of Layer objects.
        :param default_values: dictionary containing desired default values for
            missing data element values
        :raises InvalidFormat: An error indicating that the layer data
            wasn't provided in a list or dict
        """
        if isinstance(data, dict):
            temp = {}
            for entry in data.keys():
                temp[entry] = data[entry].layer.techniques
            self.mode = "dict"
            out = self._merge_to_template(data, key=list(data.keys())[0])
        elif isinstance(data, list):
            temp = []
            for entry in data:
                temp.append(entry.layer.techniques)
            self.mode = "list"
            out = self._merge_to_template(data)
        else:
            raise InvalidFormat
        da = temp
        corpus = self._build_template(temp)

        defaults = self._default_values
        if default_values is not None:
            for entry in default_values:
                defaults[entry] = default_values[entry]

        return self._compute(data, da, corpus, out, defaults)

    def _compute(self, data, da, corpus, out, defaults):
        """Apply the configured lambda to the dataset.

        :param data: the dataset being processed
        :param da: extracted techniques from the dataset, sorted by
            dataset format
        :param corpus: master list of combined techniques and
            technique data
        :param out: baseline template for the new layer
        :param defaults: default values each technique should use if a
            field is missing
        :returns: a Layer object representing the resultant layer
        """
        composite = copy.deepcopy(corpus)
        if self._score is not None:
            for entry in composite:
                entry["score"] = self._applyOperation(da, entry, "score", self._score, defaults)

        if self._comment is not None:
            for entry in composite:
                entry["comment"] = self._applyOperation(da, entry, "comment", self._comment, defaults)

        if self._enabled is not None:
            for entry in composite:
                entry["enabled"] = self._applyOperation(da, entry, "enabled", self._enabled, defaults)

        if self._colors is not None:
            for entry in composite:
                entry["color"] = self._applyOperation(da, entry, "color", self._colors, defaults)

        if self._metadata is not None:
            for entry in composite:
                entry["metadata"] = self._applyOperation(da, entry, "metadata", self._metadata, defaults)

        processed = copy.deepcopy(out)
        processed["techniques"] = composite
        if self._name is not None:
            processed["name"] = self._applyOperation(data, None, "name", self._name, defaults, glob="name")

        if self._desc is not None:
            processed["description"] = self._applyOperation(
                data, None, "description", self._desc, defaults, glob="description"
            )

        return Layer(processed)

    def _merge_to_template(self, data, key=0):
        """Merge initial layer files in either dict or list form into a single template. Defaults to the first entry in the case of difference in metadata.

        :param key: the key referencing the first entry to default to
        :raises MismatchedDomain: An error indicating that the layers
            came from different domains
        """
        out = {}
        dict_map = []
        collide = []
        if self.mode == "dict":
            for x in data.keys():
                dict_map.append(x)
                collide.append(data[x])
        else:
            for x in data:
                collide.append(x)
        key_space = data[key].layer._enumerate()
        _raw = data[key].layer.get_dict()
        for entry in key_space:
            if entry != "techniques":
                standard = _raw[entry]
                layer_entries = [getattr(x.layer, entry) for x in collide]
                layer_entries = [y.get_dict() if hasattr(y, 'get_dict') else y for y in layer_entries]
                if any(y != standard for y in layer_entries):
                    if entry == "domain":
                        print("FATAL ERROR! Layer mis-match on domain. Exiting.")
                        raise MismatchedDomain
                    print(f"Warning! Layer mis-match detected for {entry}. Defaulting to {key}'s value")
                out[entry] = standard
        return out

    def _build_template(self, data):
        """Build a base template by combining available technique listings from each layer.

        :param data: the raw ingested technique data (list or dict)
        """
        if self.mode == "list":
            return self._template(data)
        elif self.mode == "dict":
            temp = {}
            t2 = []
            for key in data:
                temp[key] = self._template([data[key]])
            for key in temp:
                for elm in temp[key]:
                    if not any(elm["techniqueID"] == x["techniqueID"] and elm["tactic"] == x["tactic"] for x in t2):
                        t2.append(elm)
                    else:
                        [
                            x.update(elm)
                            if x["techniqueID"] == elm["techniqueID"] and elm["tactic"] == x["tactic"]
                            else x
                            for x in t2
                        ]
            return t2

    @staticmethod
    def _template(data):
        """Create a template technique entry for a given listing of techniques.

        :param data: a single layer's technique data
        :returns: a list of technique templates
        """
        temp = []
        for entry in data:
            temp.append(
                [
                    {"techniqueID": x.techniqueID, "tactic": x.tactic} if x.tactic else {"techniqueID": x.techniqueID}
                    for x in entry
                ]
            )
        complete = []
        for entry in temp:
            for val in entry:
                if val in complete:
                    continue
                complete.append(val)
        return complete

    def _grabList(self, search, collection):
        """Generate a list containing all values for a given key across the collection.

        :param search: the key to search for
        :param collection: the data collection to search
        :returns: a list of values for that key across the collection
        """
        temp = []
        for x in collection:
            temp.append(self._grabElement(search, x))
        return temp

    def _grabDict(self, search, collection):
        """Generate a dictionary containing all values for a given key across the collection.

        :param search: the key to search for
        :param collection: the data collection to search
        :returns: a dict of values for that key across the collection
        """
        temp = {}
        for key in collection:
            temp[key] = self._grabElement(search, collection[key])
        return temp

    def _grabElement(self, search, listing):
        """Return a matching element in the listing for the search key.

        :param search: the key to search for
        :param listing: the data element to search
        :returns: the found value, or an empty dict
        """
        val = [x for x in listing if self._inDict(search, x)]
        if len(val) > 0:
            return val[0]
        return {}

    @staticmethod
    def _inDict(search, complete):
        """Return bool of whether or not the key searched for can be found across the dataset corpus.

        :param search: the key to search for
        :param complete: the data set to search for
        :returns: true/false
        """
        comp_list = complete.get_dict().items()
        search_terms = search.items()
        return all(elm in comp_list for elm in search_terms)

    def _applyOperation(self, corpus, element, name, lda, defaults, glob=None):
        """Apply a lambda expression to the dataset.

        :param corpus: the dataset
        :param element: the template file to fill out
        :param name: the name of the field being processed
        :param lda: the lambda expression to apply
        :param defaults: any default values should the field not be found
            in a dataset entry
        :raises BadLambda: error denoting that an error has occurred when
            running the lambda function
        :returns: lambda output
        """
        if self.mode == "list":
            if glob:
                listing = [getattr(x.layer, glob) for x in corpus]
                listing = [{name: x} for x in listing]
            else:
                te = dict(techniqueID=element["techniqueID"])
                if "tactic" in element:
                    te["tactic"] = element["tactic"]
                listing = self._grabList(te, corpus)
                listing = [x.get_dict() if not isinstance(x, dict) else dict() for x in listing]
            values = []
            for x in listing:
                if name in x:
                    values.append(x[name])
                else:
                    if defaults is not None:
                        if name in defaults:
                            values.append(defaults[name])
                            continue
                    values.append(self._default_values[name])
        else:
            values = {}
            if glob:
                listing = {}
                for k in corpus.keys():
                    listing[k] = {glob: getattr(corpus[k].layer, glob)}
            else:
                te = dict(techniqueID=element["techniqueID"])
                if "tactic" in element:
                    te["tactic"] = element["tactic"]
                temp = self._grabDict(te, corpus)
                listing = {}
                for k in temp.keys():
                    if temp[k] != {}:
                        listing[k] = temp[k].get_dict()
                    else:
                        listing[k] = {}
            for elm in listing:
                if name in listing[elm]:
                    values[elm] = listing[elm][name]
                else:
                    if defaults is not None:
                        if name in defaults:
                            values[elm] = defaults[name]
                            continue
                    values[elm] = self._default_values[name]
        try:
            return lda(values)
        except IndexError and KeyError:
            print(
                'Unable to continue, lambda targeting "{}" could not operate'
                " correctly on {}. Maybe the field is missing?".format(name, element)
            )
            print(f"[RAW] Extracted matching elements: {listing}")
            raise BadLambda
