"""Build a CWE-ID -> {name, description, example} lookup from the MITRE CWE XML catalog.

The original BILVR datasets populate four CWE columns (CWE ID, CWE Name, CWE
Description, CWE Example) from MITRE. Only the CWE ID is carried by a vulnerability
dataset (via its CWE label); the other three are catalog-derived here so that any
CVE-keyed dataset can be lifted into the BILVR 10-column format.

- CWE Description = Description (+ Extended Description when present).
- CWE Example     = the first Demonstrative Example, rendered from xhtml: <br/> ->
                    newline, highlighted <div style=...> (MITRE's "added/changed"
                    markup) -> a leading "+ " on each affected line, <i> kept as-is.
                    This mirrors the diff-style look of the original CWE Example
                    column; exact byte-for-byte text differs across CWE versions.
"""
import re
import xml.etree.ElementTree as ET

CWE_NS = "http://cwe.mitre.org/cwe-7"
XHTML_NS = "http://www.w3.org/1999/xhtml"
_NS = {"c": CWE_NS, "x": XHTML_NS}


def _qn(tag: str) -> str:
    return f"{{{XHTML_NS}}}{tag}"


def _render_node(node, highlighted: bool, out: list[str]) -> None:
    """Flatten mixed xhtml content into text, turning <br/> into newlines and
    MITRE's highlight wrapper divs (style attribute present) into '+ ' line prefixes."""
    tag = node.tag.split("}")[-1] if "}" in node.tag else node.tag
    is_highlight = tag == "div" and bool(node.get("style"))
    here = highlighted or is_highlight

    if node.text:
        out.append(("\x00" if here else "") + node.text if out and out[-1].endswith("\n") else node.text)

    for child in node:
        ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if ctag == "br":
            out.append("\n")
        else:
            _render_node(child, here, out)
        if child.tail:
            out.append(child.tail)


def _example_to_text(example_code) -> str:
    parts: list[str] = []
    _render_node(example_code, False, parts)
    text = "".join(parts)
    # Convert the highlight sentinel (\x00 on a highlighted line) to a '+ ' prefix.
    raw = []
    for ln in text.split("\n"):
        if "\x00" in ln:
            raw.append("+ " + ln.replace("\x00", "").strip())
        else:
            raw.append(ln.rstrip())
    # Strip the common leading indentation introduced by XML pretty-printing,
    # then drop leading/trailing blank lines and collapse blank runs.
    body = [l for l in raw if l.strip()]
    if body:
        indent = min(len(l) - len(l.lstrip(" ")) for l in body if not l.startswith("+"))
        raw = [l[indent:] if (l.strip() and not l.startswith("+")) else l for l in raw]
    out, blanks = [], 0
    for l in raw:
        if not l.strip():
            blanks += 1
            if blanks <= 1 and out:
                out.append("")
        else:
            blanks = 0
            out.append(l)
    while out and not out[0].strip():
        out.pop(0)
    if out:
        out[0] = out[0].lstrip()  # drop XML pretty-print indent leaking onto line 1
    return "\n".join(out).strip("\n")


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return re.sub(r"[ \t]+", " ", text.replace("\n", " ")).strip()


def build_cwe_lookup(xml_path: str) -> dict[str, dict]:
    """Return {'CWE-190': {'name': ..., 'description': ..., 'example': ...}, ...}."""
    root = ET.parse(xml_path).getroot()
    lookup: dict[str, dict] = {}
    for kind in ("Weakness", "Category"):
        for w in root.iter(f"{{{CWE_NS}}}{kind}"):
            cid = w.get("ID")
            if not cid:
                continue
            desc = _clean(w.findtext("c:Description", default="", namespaces=_NS))
            ext = _clean(w.findtext("c:Extended_Description", default="", namespaces=_NS))
            full_desc = (desc + (" " + ext if ext else "")).strip()

            example = ""
            de = w.find("c:Demonstrative_Examples", _NS)
            if de is not None:
                ec = de.find(".//c:Example_Code", _NS)
                if ec is not None:
                    example = _example_to_text(ec)

            lookup[f"CWE-{cid}"] = {
                "name": w.get("Name", ""),
                "description": full_desc,
                "example": example,
            }
    return lookup


if __name__ == "__main__":
    import sys
    lk = build_cwe_lookup(sys.argv[1] if len(sys.argv) > 1 else "cwec_v4.20.xml")
    print(f"loaded {len(lk)} CWE entries")
    for cid in ("CWE-190", "CWE-79", "CWE-119"):
        e = lk.get(cid, {})
        print(f"\n===== {cid}: {e.get('name')} =====")
        print("DESC:", e.get("description", "")[:200])
        print("EXAMPLE:\n", e.get("example", "")[:300])
