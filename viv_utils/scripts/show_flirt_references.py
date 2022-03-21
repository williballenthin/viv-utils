import sys
import gzip
import logging
import argparse
import binascii

import flirt
import vivisect.const

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


def get_workspace(path, sigpaths):
    vw = viv_utils.getWorkspace(path, analyze=False, should_save=False)
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

    sigs = load_flirt_signature(args.signature)
    logger.debug("flirt: sig count: %d", len(sigs))
    matcher = flirt.compile(sigs)

    seen = set()

    for function in vw.getFunctions():
        buf = viv_utils.readMemoryCurrentSection(vw, function, 0x10000)

        for match in matcher.match(buf):
            references = list(filter(lambda n: n[1] == "reference" and (function + n[2]) not in seen, match.names))

            if not references:
                continue

            print("matching function: 0x%x" % (function))
            print("  candidate match: 0x%x: %s" % (function, match))

            print("  references:")

            for (ref_name, _, ref_offset) in references:
                ref_va = function + ref_offset
                seen.add(ref_va)

                print("  - 0x%x: %s" % (ref_va, ref_name))

                loc = vw.getLocation(ref_va)
                loc_va = loc[vivisect.const.L_VA]
                print("    loc: 0x%x" % (loc_va))
                print("    delta: 0x%x" % (ref_va - loc_va))

                size = loc[vivisect.const.L_SIZE]
                buf = viv_utils.readMemoryCurrentSection(vw, loc_va, size)
                print("    bytes: %s" % (binascii.hexlify(buf).decode("ascii")))

                print("           %s^" % ("  " * (ref_va - loc_va)))

                insn = vw.parseOpcode(loc_va)
                print("    insn: %s" % (insn))

                print("    xrefs:")
                for xref in sorted(set(map(lambda x: x[vivisect.const.XR_TO], vw.getXrefsFrom(loc_va)))):
                    print("    - 0x%x" % (xref))

        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
