import logging

# this is py3 only
import flirt
import vivisect
import viv_utils

logger = logging.getLogger(__name__)


# vivisect funcmeta key for a bool to indicate if a function is recognized from a library.
# not expecting anyone to use this, aka private symbol.
_LIBRARY_META_KEY = "is-library"


def is_library_function(vw, va):
    """
    is the function at the given address a library function?
    this may be determined by a signature matching backend.
    if there's no function at the given address, `False` is returned.

    note: if its a library function, it should also have a name set.

    args:
      vw (vivisect.Workspace):
      va (int): the virtual address of a function.

    returns:
      bool: if the function is recognized as from a library.
    """
    return vw.funcmeta.get(va, {}).get(_LIBRARY_META_KEY, False)


def make_library_function(vw, va):
    """
    mark the function with the given address a library function.
    the associated accessor is `is_library_function`.

    if there's no function at the given address, this routine has no effect.

    note: if its a library function, it should also have a name set.
    its up to the caller to do this part.

    args:
      vw (vivisect.Workspace):
      va (int): the virtual address of a function.
    """
    fmeta = vw.funcmeta.get(va, {})
    fmeta[_LIBRARY_META_KEY] = True


def add_function_flirt_match(vw, va, name):
    """
    mark the function at the given address as a library function with the given name.
    the name overrides any existing function name.

    args:
      vw (vivisect.Workspace):
      va (int): the virtual address of a function.
      name (str): the name to assign to the function.
    """
    make_library_function(vw, va)
    viv_utils.set_function_name(vw, va, name)


def get_match_name(match):
    """
    fetch the best name for a `flirt.FlirtSignature` instance.
    these instances returned by `flirt.FlirtMatcher.match()`
    may have multiple names, such as public and local names for different parts
    of a function. the best name is that at offset zero (the function name).

    probably every signature has a best name, though I'm not 100% sure.

    args:
      match (flirt.FlirtSignature): the signature to get a name from.

    returns:
      str: the best name of the function matched by the given signature.
    """
    for (name, type_, offset) in match.names:
        if offset == 0:
            return name
    raise ValueError("flirt: match: no best name: %s", match.names)


def match_function_flirt_signatures(matcher: flirt.FlirtMatcher, vw: vivisect.VivWorkspace, va: int):
    """
    match the given FLIRT signatures against the function at the given address.
    upon success, update the workspace with match metadata, setting the
    function as a library function and assigning its name.

    if multiple different signatures match the function, don't do anything.

    args:
      match (flirt.FlirtMatcher): the compiled FLIRT signature matcher.
      vw (vivisect.workspace): the analyzed program's workspace.
      va (int): the virtual address of a function to match.

    returns:
      Optional[str]: the recognized function name, or `None`.
    """
    function_meta = vw.funcmeta.get(va)
    if not function_meta:
        # not a function, we're not going to consider this.
        return None

    if is_library_function(vw, va):
        # already matched here.
        # this might be the case if recursive matching visited this address.
        return viv_utils.get_function_name(vw, va)

    # 0x200 comes from:
    #  0x20 bytes for default byte signature size in flirt
    #  0x100 bytes for max checksum data size
    #  some wiggle room for tail bytes
    size = function_meta.get("Size", 0x200)
    # viv returns truncated data at the end of sections,
    # no need for any special logic here.
    buf = vw.readMemory(va, size)

    matches = []
    for match in matcher.match(buf):
        # collect all the name tuples (name, type, offset) with type==reference.
        # ignores other name types like "public" and "local".
        references = list(filter(lambda n: n[1] == "reference", match.names))

        if not references:
            # there are no references that we need to check, so this is a complete match.
            # common case.
            matches.append(match)

        else:
            # flirt uses reference names to assert that
            # the function contains a reference to another function with a given name.
            #
            # we need to loop through these references,
            # potentially recursively FLIRT match,
            # and check the name matches (or doesn't).

            # at the end of the following loop,
            # if this flag is still true,
            # then all the references have been validated.
            does_match_references = True

            #logger.debug("references needed for name %s for function at 0x%x: %s", get_match_name(match), va, references)

            # when a reference is used to differentiate rule matches,
            # then we can expect multiple rules to query the name of the same address.
            # so, this caches the names looked up in the below loop.
            # type: Map[int, str]
            local_names = {}
            for (ref_name, _, ref_offset) in references:
                ref_va = va + ref_offset

                # the reference offset may be inside an instruction,
                # so we use getLocation to select the containing instruction address.
                loc_va = vw.getLocation(ref_va)[vivisect.const.L_VA]

                # an instruction may have multiple xrefs from
                # so we loop through all code references,
                # searching for that name.
                #
                # TODO: if we assume there is a single code reference, this is a lot easier.
                # can we do that with FLIRT?
                #
                # if the name is found, then this flag will be set.
                does_match_the_reference = False
                for xref in vw.getXrefsFrom(loc_va):
                    # FLIRT signatures only match code,
                    # so we're only going to resolve references that point to code.
                    if xref[vivisect.const.XR_RTYPE] != vivisect.const.REF_CODE:
                        continue

                    target = xref[vivisect.const.XR_TO]
                    if target in local_names:
                        # fast path: a prior loop already looked up this address.
                        found_name = local_names[target]
                    else:
                        # this is a bit slower, since we have to read buf, do match, etc.
                        # note that we don't ever save "this is not a library function",
                        # so there's not an easy way to short circuit at the start of this function.
                        found_name = match_function_flirt_signatures(matcher, vw, target)
                        local_names[target] = found_name

                    #logger.debug("reference: 0x%x: 0x%x: wanted: %s found: %s", loc_va, target, ref_name, found_name)

                    if found_name == ref_name:
                        does_match_the_reference = True
                        break

                if not does_match_the_reference:
                    does_match_references = False
                    break

            if does_match_references:
                # only if all references pass do we count it.
                matches.append(match)

    if matches:
        # we may have multiple signatures that match the same function, like `strcpy`.
        # these could be copies from multiple libraries.
        # so we don't mind if there are multiple matches, as long as names are the same.
        #
        # but if there are multiple candidate names, that's a problem.
        # our signatures are not precise enough.
        # we could maybe mark the function as "is a library function", but not assign name.
        # though, if we have signature FPs among library functions, it could easily FP with user code too.
        # so safest thing to do is not make any claim about the function.
        names = list(set(map(get_match_name, matches)))
        if len(names) == 1:
            name = names[0]
            add_function_flirt_match(vw, va, name)
            logger.debug("found library function: 0x%x: %s", va, name)
            return name
        else:
            logger.warning("conflicting names: 0x%x: %s", va, names)
            return None


class FlirtFunctionAnalyzer:
    def __init__(self, matcher: flirt.FlirtMatcher, name=None):
        self.matcher = matcher
        self.name = name

    def analyzeFunction(self, vw: vivisect.VivWorkspace, funcva: int):
        match_function_flirt_signatures(self.matcher, vw, funcva)

    def __repr__(self):
        if self.name:
            return f"{self.__class__.__name__} ({self.name})"
        else:
            return f"{self.__class__.__name__}"


def addFlirtFunctionAnalyzer(vw: vivisect.VivWorkspace, analyzer: FlirtFunctionAnalyzer):
    # this is basically the logic in `vivisect.VivWorkspace.addFuncAnalysisModule`.
    # however, that routine assumes the analyzer is a Python module, which is basically a global,
    # and i am very against globals.
    # so, we manually place the analyzer into the analyzer queue.
    #
    # notably, this enables a user to register multiple FlirtAnalyzers for different signature sets.
    key = repr(analyzer)

    if key in vw.fmodlist:
        raise ValueError("analyzer already present")

    vw.fmodlist.append(key)
    vw.fmods[key] = analyzer