import sys
import gzip
import logging
import argparse

import flirt

import viv_utils
import viv_utils.flirt

logger = logging.getLogger("get_flirt_matches")


def load_flirt_signature(path):
    if path.endswith(".sig"):
        with open(path, "rb") as f:
            sigs = flirt.parse_sig(f.read())

    elif path.endswith(".pat"):
        with open(path, "rb") as f:
            sigs = flirt.parse_pat(f.read().decode("utf-8"))

    elif path.endswith(".pat.gz"):
        with gzip.open(path, "rb") as f:
            sigs = flirt.parse_pat(f.read().decode("utf-8"))

    else:
        raise ValueError("unexpect signature file extension: " + path)

    return sigs


def register_flirt_signature_analyzers(vw, sigpaths):
    """
    args:
      vw (vivisect.VivWorkspace):
      sigpaths (List[str]): file system paths of .sig/.pat files
    """
    for sigpath in sigpaths:
        sigs = load_flirt_signature(sigpath)

        logger.debug("flirt: sig count: %d", len(sigs))

        matcher = flirt.compile(sigs)

        analyzer = viv_utils.flirt.FlirtFunctionAnalyzer(matcher, sigpath)
        logger.debug("registering viv function analyzer: %s", repr(analyzer))
        viv_utils.flirt.addFlirtFunctionAnalyzer(vw, analyzer)


def get_workspace(path, sigpaths):
    vw = viv_utils.getWorkspace(path, analyze=False, should_save=False)
    register_flirt_signature_analyzers(vw, sigpaths)
    vw.analyze()
    return vw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    parser.add_argument(
        "signature",
        type=str,
        help="use the given signatures to identify library functions, file system paths to .sig/.pat files.",
    )
    parser.add_argument(
        "sample",
        type=str,
        help="path to sample to analyze",
    )

    args = parser.parse_args()

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

        logging.getLogger("vivisect").setLevel(logging.INFO)
        logging.getLogger("vivisect.base").setLevel(logging.INFO)
        logging.getLogger("vivisect.impemu").setLevel(logging.INFO)
        logging.getLogger("vtrace").setLevel(logging.INFO)
        logging.getLogger("envi").setLevel(logging.INFO)
        logging.getLogger("envi.codeflow").setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger("vivisect").setLevel(logging.WARNING)

    vw = get_workspace(args.sample, [args.signature])

    names = set()
    for va in sorted(vw.getFunctions()):
        if viv_utils.flirt.is_library_function(vw, va):
            name = viv_utils.get_function_name(vw, va)
            print("0x%x: %s" % (va, name))
            names.add(name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
