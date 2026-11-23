"""
Package Version and Release Comparison Engine.
Implements the RPM rpmvercmp algorithm and Debian version comparison algorithm.
Authoritative comparison for vendor backported packages, epochs, versions, and releases.
"""

import re
from typing import Tuple, List, Union


def rpmvercmp(a: str, b: str) -> int:
    """
    Python implementation of RPM's rpmvercmp(3) library function.
    Returns:
       1 if a > b
       0 if a == b
      -1 if a < b
    """
    if a == b:
        return 0

    idx_a = 0
    idx_b = 0
    len_a = len(a)
    len_b = len(b)

    while idx_a < len_a or idx_b < len_b:
        # 1. Skip non-alphanumeric chars (except ~ and ^)
        while idx_a < len_a and not a[idx_a].isalnum() and a[idx_a] not in "~^":
            idx_a += 1
        while idx_b < len_b and not b[idx_b].isalnum() and b[idx_b] not in "~^":
            idx_b += 1

        # 2. Handle tildes: '~' sorts before anything else
        if (idx_a < len_a and a[idx_a] == "~") or (idx_b < len_b and b[idx_b] == "~"):
            if idx_a >= len_a or a[idx_a] != "~":
                return 1
            if idx_b >= len_b or b[idx_b] != "~":
                return -1
            idx_a += 1
            idx_b += 1
            continue

        # 3. Handle carets: '^' sorts after empty, but before any non-empty
        if (idx_a < len_a and a[idx_a] == "^") or (idx_b < len_b and b[idx_b] == "^"):
            if idx_a >= len_a:
                return -1
            if idx_b >= len_b:
                return 1
            if a[idx_a] == "^" and b[idx_b] != "^":
                return -1
            if a[idx_a] != "^" and b[idx_b] == "^":
                return 1
            idx_a += 1
            idx_b += 1
            continue

        # If we reached the end of either string
        if idx_a >= len_a or idx_b >= len_b:
            break

        # 4. Extract digits or letters
        is_num = a[idx_a].isdigit()
        if is_num:
            start_a = idx_a
            while idx_a < len_a and a[idx_a].isdigit():
                idx_a += 1
            start_b = idx_b
            while idx_b < len_b and b[idx_b].isdigit():
                idx_b += 1

            if start_b == idx_b or not b[start_b].isdigit():
                return 1  # numbers are greater than letters in RPM

            # Trim leading zeros for numerical comparison
            seg_a = a[start_a:idx_a].lstrip("0") or "0"
            seg_b = b[start_b:idx_b].lstrip("0") or "0"

            val_a = int(seg_a)
            val_b = int(seg_b)
            if val_a < val_b:
                return -1
            if val_a > val_b:
                return 1
        else:
            start_a = idx_a
            while idx_a < len_a and a[idx_a].isalpha():
                idx_a += 1
            start_b = idx_b
            while idx_b < len_b and b[idx_b].isalpha():
                idx_b += 1

            if start_b == idx_b or not b[start_b].isalpha():
                return -1  # letters are less than numbers

            seg_a = a[start_a:idx_a]
            seg_b = b[start_b:idx_b]
            if seg_a < seg_b:
                return -1
            if seg_a > seg_b:
                return 1

    if idx_a >= len_a and idx_b >= len_b:
        return 0
    if idx_a >= len_a:
        # String a ended first
        # If b starts with '~', then a is newer
        if idx_b < len_b and b[idx_b] == "~":
            return 1
        return -1
    else:
        # String b ended first
        if idx_a < len_a and a[idx_a] == "~":
            return -1
        return 1


def compare_rpm_evr(
    e1: Union[str, int], v1: str, r1: str,
    e2: Union[str, int], v2: str, r2: str
) -> int:
    """
    Compares two RPM EVRs (Epoch:Version-Release).
    Returns 1 if evr1 > evr2, 0 if equal, -1 if evr1 < evr2.
    """
    # Compare epochs
    ep1 = int(e1) if str(e1).isdigit() else 0
    ep2 = int(e2) if str(e2).isdigit() else 0

    if ep1 < ep2:
        return -1
    elif ep1 > ep2:
        return 1

    # Compare versions
    rc = rpmvercmp(v1, v2)
    if rc != 0:
        return rc

    # Compare releases
    return rpmvercmp(r1, r2)


def parse_rpm_nevra(nevra_str: str) -> Tuple[str, str, str, str, str]:
    """
    Parses an RPM string into (name, epoch, version, release, arch).
    Supports formats like:
      nginx-1:1.20.1-14.el9_2.1.x86_64
      nginx-1.20.1-14.el9_2.1.x86_64
      nginx-1.20.1-14.el9_2.1
    """
    # Strip arch if present at end
    arch = ""
    parts = nevra_str.rsplit(".", 1)
    if len(parts) == 2 and parts[1] in ["x86_64", "aarch64", "noarch", "i686", "armv7hl", "s390x", "ppc64le"]:
        nevra_str = parts[0]
        arch = parts[1]

    # Split name and version-release
    # Last hyphen separates version-release from name, but there is also a hyphen between version and release
    hyphen_parts = nevra_str.rsplit("-", 2)
    if len(hyphen_parts) == 3:
        name = hyphen_parts[0]
        ver_str = hyphen_parts[1]
        rel_str = hyphen_parts[2]
    elif len(hyphen_parts) == 2:
        name = hyphen_parts[0]
        ver_str = hyphen_parts[1]
        rel_str = ""
    else:
        return (nevra_str, "0", "", "", arch)

    # Check for epoch in version
    if ":" in ver_str:
        epoch, version = ver_str.split(":", 1)
    else:
        epoch = "0"
        version = ver_str

    return (name, epoch, version, rel_str, arch)


def debvercmp(a: str, b: str) -> int:
    """
    Debian dpkg version comparison algorithm.
    Returns 1 if a > b, 0 if equal, -1 if a < b.
    """
    if a == b:
        return 0

    # Debian format: [epoch:]upstream_version[-debian_revision]
    def split_deb_version(v: str) -> Tuple[int, str, str]:
        epoch = 0
        if ":" in v:
            ep_str, rest = v.split(":", 1)
            epoch = int(ep_str) if ep_str.isdigit() else 0
        else:
            rest = v

        if "-" in rest:
            upstream, deb_rev = rest.rsplit("-", 1)
        else:
            upstream = rest
            deb_rev = "0"
        return epoch, upstream, deb_rev

    ep_a, up_a, rev_a = split_deb_version(a)
    ep_b, up_b, rev_b = split_deb_version(b)

    if ep_a != ep_b:
        return 1 if ep_a > ep_b else -1

    def deb_order(ch: str) -> int:
        if not ch:
            return 0
        if ch == "~":
            return -1
        if ch.isalpha():
            return ord(ch)
        return ord(ch) + 256

    def deb_frag_cmp(val: str, ref: str) -> int:
        i1, i2 = 0, 0
        len1, len2 = len(val), len(ref)

        while i1 < len1 or i2 < len2:
            first_diff = 0
            while (i1 < len1 and not val[i1].isdigit()) or (i2 < len2 and not ref[i2].isdigit()):
                c1 = val[i1] if i1 < len1 and not val[i1].isdigit() else ""
                c2 = ref[i2] if i2 < len2 and not ref[i2].isdigit() else ""
                vc = deb_order(c1)
                rc = deb_order(c2)
                if vc != rc:
                    return 1 if vc > rc else -1
                if c1:
                    i1 += 1
                if c2:
                    i2 += 1

            # Strip leading zeros
            while i1 < len1 and val[i1] == "0":
                i1 += 1
            while i2 < len2 and ref[i2] == "0":
                i2 += 1

            while i1 < len1 and val[i1].isdigit() and i2 < len2 and ref[i2].isdigit():
                if first_diff == 0:
                    first_diff = ord(val[i1]) - ord(ref[i2])
                i1 += 1
                i2 += 1

            if i1 < len1 and val[i1].isdigit():
                return 1
            if i2 < len2 and ref[i2].isdigit():
                return -1
            if first_diff != 0:
                return 1 if first_diff > 0 else -1

        return 0

    rc_up = deb_frag_cmp(up_a, up_b)
    if rc_up != 0:
        return rc_up

    return deb_frag_cmp(rev_a, rev_b)
