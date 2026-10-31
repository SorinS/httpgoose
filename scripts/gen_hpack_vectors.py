#!/usr/bin/env python3
"""RFC 7541 Appendix C's examples as vectors for test/hpack.goose, taken
from golang.org/x/net/http2/hpack's hpack_test.go (which quotes them):

  series LIMIT       a decoder with SETTINGS_HEADER_TABLE_SIZE = LIMIT
  block HEX          a header block, then what it decodes to:
  field NAME VALUE S each field (S: 1 if never indexed)
  table NAME VALUE   the dynamic table after it, newest first
  size N             and its size (RFC 7541 §4.1)

written to test/vectors/hpack_rfc.txt (tab-separated).

    python3 scripts/gen_hpack_vectors.py [--xnet VERSION]
"""

import argparse
import os
import re
import subprocess

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def fields(text):
    out = []
    for m in re.finditer(r'pair\("([^"]*)", "([^"]*)"\)|\{"([^"]*)", "([^"]*)", (true|false)\}', text):
        if m.group(1) is not None:
            out.append((m.group(1), m.group(2), 0))
        else:
            out.append((m.group(3), m.group(4), 1 if m.group(5) == "true" else 0))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xnet", default="v0.58.0")
    args = ap.parse_args()
    modcache = subprocess.run(["go", "env", "GOMODCACHE"], capture_output=True, text=True, check=True).stdout.strip()
    src = open(os.path.join(modcache, "golang.org", "x", f"net@{args.xnet}", "http2", "hpack", "hpack_test.go")).read()
    lines = [f"# RFC 7541 Appendix C, as golang.org/x/net {args.xnet}'s hpack_test.go quotes it; scripts/gen_hpack_vectors.py"]
    # C.2: one block each, on a fresh 4096 decoder.
    body = src[src.index("func TestDecoderDecode"):src.index("func (dt *dynamicTable) reverseCopy")]
    for m in re.finditer(r'\{"(C\.2\.\d)", (?:dehex\("([0-9a-f ]+)"\)|\[\]byte\("\\x([0-9a-f]{2})"\)),\s*\[\]HeaderField\{(.*?)\},\s*\[\]HeaderField\{(.*?)\}', body, re.S):
        hexs = (m.group(2) or m.group(3)).replace(" ", "")
        lines.append(f"series\t4096\t{m.group(1)}")
        lines.append(f"block\t{hexs}")
        for n, v, s in fields(m.group(4)):
            lines.append(f"field\t{n}\t{v}\t{s}")
        for n, v, s in fields(m.group(5)):
            lines.append(f"table\t{n}\t{v}")
    # C.3 to C.6: series of blocks on one decoder.
    for name in ("TestDecodeC3_NoHuffman", "TestDecodeC4_Huffman", "TestDecodeC5_ResponsesNoHuff", "TestDecodeC6_ResponsesHuffman"):
        start = src.index(f"func {name}")
        end = src.index("\n}\n", start)
        fn = src[start:end]
        limit = re.search(r"testDecodeSeries\(t, (\d+),", fn).group(1)
        tag = {"TestDecodeC3_NoHuffman": "C.3", "TestDecodeC4_Huffman": "C.4",
               "TestDecodeC5_ResponsesNoHuff": "C.5", "TestDecodeC6_ResponsesHuffman": "C.6"}[name]
        lines.append(f"series\t{limit}\t{tag}")
        for m in re.finditer(r'\{dehex\((?:"([0-9a-f ]+)"|`([0-9a-f \n]+)`)\),\s*\[\]HeaderField\{(.*?)\},\s*\[\]HeaderField\{(.*?)\},\s*(\d+),', fn, re.S):
            hexs = re.sub(r"\s", "", m.group(1) or m.group(2))
            lines.append(f"block\t{hexs}")
            for n, v, s in fields(m.group(3)):
                lines.append(f"field\t{n}\t{v}\t{s}")
            for n, v, s in fields(m.group(4)):
                lines.append(f"table\t{n}\t{v}")
            lines.append(f"size\t{m.group(5)}")
    with open(os.path.join(ROOT, "test", "vectors", "hpack_rfc.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(sum(l.startswith("block") for l in lines), "blocks")


if __name__ == "__main__":
    main()
