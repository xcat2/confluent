#!/usr/bin/env python3
"""Manage retrieval of OS material from locations, including GPG validation where possible."""

import asyncio
import hashlib
import os
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from html.parser import HTMLParser

import aiohttp


@dataclass
class DownloadInfo:
    """A single downloadable ISO and its verification metadata."""

    architecture: str = ""
    distro: str = ""
    gpg_status: str = ""
    iso_name: str = ""
    iso_sha256: str = ""
    iso_url: str = ""
    release: str = ""


EL_DISTROS = {
    "rocky": {
        "name": "Rocky Linux",
        "base_url": "https://download.rockylinux.org/pub/rocky/",
        "gpg_key_url_pattern": "https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-{major}",
        "sig_style": "detached",           # default for new releases
        "sig_style_overrides": {            # older releases lack sigs
            "8": "none",
            "9": "none",
        },
    },
    "alma": {
        "name": "AlmaLinux",
        "base_url": "https://repo.almalinux.org/almalinux/",
        "gpg_key_url_pattern": "https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-{major}",
        "sig_style": "inline",
    },
}

# Ubuntu uses a different mirror layout: per-release directories containing the
# ISOs alongside a SHA256SUMS file and a binary detached SHA256SUMS.gpg
# signature made with the Ubuntu CD Image Automatic Signing Keys.
UBUNTU = {
    "name": "Ubuntu Server",
    "base_url": "https://releases.ubuntu.com/",
    # (ubuntu_arch, per-release directory URL pattern; {ver} is the release).
    # amd64 images live on releases.ubuntu.com; other arches on cdimage.
    "sources": [
        ("amd64", "https://releases.ubuntu.com/{ver}/"),
        ("arm64", "https://cdimage.ubuntu.com/releases/{ver}/release/"),
    ],
    "gpg_key_urls": [
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search="
        "0x843938DF228D22F7B3742BC0D94AA3F0EFE21092",
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search="
        "0xC5986B4F1257FFA86632CBA746181433FBB75451",
    ],
}

# Debian publishes the installer 'mini.iso' under each suite's installer tree.
# There is no signature next to the images; trust flows from the suite's
# clear-signed InRelease file, whose SHA256 section covers the per-arch
# SHA256SUMS file, which in turn lists mini.iso.
DEBIAN = {
    "name": "Debian",
    "mirror": "https://deb.debian.org/debian/",
    # (suite codename, Debian version used to pick the archive signing key).
    "suites": [
        ("bullseye", "11"),
        ("bookworm", "12"),
        ("trixie", "13"),
    ],
    "archive_key_url_pattern": (
        "https://ftp-master.debian.org/keys/archive-key-{ver}.asc"
    ),
    # confluent arch -> Debian arch.
    "arches": ["amd64", "arm64"],
}

SUPPORTED_ARCHS = ("aarch64", "x86_64")
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)
# Large ISO downloads must not be capped by a total timeout; bound stalls only.
DOWNLOAD_TIMEOUT = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=60)


# Many of the OS download sites are auto generated HTML indexes, we must parse them
class DirectoryParser(HTMLParser):
    """Extract href links from an nginx/apache directory listing page."""

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value and not value.startswith(".."):
                    self.links.append(value)


async def fetch_url(session, url):
    """Return the body of *url* as a string, or None on error."""
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            return await resp.text(errors="replace")
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        print(f"  WARNING: could not fetch {url}: {exc}", file=sys.stderr)
        return None


async def fetch_bytes(session, url):
    """Return the raw body of *url* as bytes, or None on error."""
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            return await resp.read()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        print(f"  WARNING: could not fetch {url}: {exc}", file=sys.stderr)
        return None


async def fetch_links(session, url):
    """Return list of href values found at *url*."""
    html = await fetch_url(session, url)
    if html is None:
        return []
    parser = DirectoryParser()
    parser.feed(html)
    return parser.links


def _parse_major_versions(links):
    """Filter link list down to bare major-version directory names."""
    versions = []
    for link in links:
        name = link.strip("/")
        if re.fullmatch(r"\d+", name):
            versions.append(name)
    return sorted(versions, key=int)


def _parse_point_releases(links, major):
    """Filter link list down to point-release directory names for *major*."""
    releases = []
    for link in links:
        name = link.strip("/")
        if re.fullmatch(rf"{major}\.\d+", name):
            releases.append(name)
    return sorted(releases, key=lambda v: list(map(int, v.split("."))))


def _parse_architectures(links):
    """Filter link list down to supported architecture directory names."""
    arch_re = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]+$")
    arches = []
    for link in links:
        name = link.strip("/")
        if arch_re.match(name) and name in SUPPORTED_ARCHS:
            arches.append(name)
    return sorted(arches)


def _parse_checksums(body):
    """Parse a CHECKSUM file body into {filename: sha256_hex}."""
    checksums = {}
    if body is None:
        return checksums
    sha_re = re.compile(r"^SHA256\s*\((.+?)\)\s*=\s*([0-9a-fA-F]+)", re.MULTILINE)
    for m in sha_re.finditer(body):
        checksums[m.group(1)] = m.group(2).lower()
    return checksums


def _parse_el_isos(links, iso_dir):
    """Filter link list down to .iso entries, returning [(name, url), …]."""
    isos = []
    for link in links:
        name = link.strip("/")
        if name.lower().endswith("-dvd.iso"):
            isos.append((name, iso_dir + name))
            return sorted(isos)
    return sorted(isos)


def _parse_ubuntu_versions(links):
    """Filter link list down to two-component release dirs (e.g. '24.04')."""
    versions = set()
    for link in links:
        name = link.strip("/")
        if re.fullmatch(r"\d+\.\d+", name):
            versions.add(name)
    return sorted(versions, key=lambda v: list(map(int, v.split("."))))


def _parse_ubuntu_point_releases(links, version):
    """Filter link list down to point-release dirs for *version*."""
    releases = []
    for link in links:
        name = link.strip("/")
        if re.fullmatch(rf"{re.escape(version)}\.\d+", name):
            releases.append(name)
    return sorted(releases, key=lambda v: list(map(int, v.split("."))))


def _parse_ubuntu_server_isos(links, arch, iso_dir):
    """Filter link list down to server install .iso entries for *arch*."""
    iso_re = re.compile(
        rf"^ubuntu-.*-(?:live-)?server-{re.escape(arch)}(?:\+[a-z0-9]+)?\.iso$"
    )
    isos = set()
    for link in links:
        name = link.strip("/")
        if iso_re.match(name) and "preinstalled" not in name:
            isos.add((name, iso_dir + name))
    highestver = None
    for curriso in isos:
        distro, ver, _ = curriso[0].split("-", 2)
        if highestver is None or list(map(int, ver.split("."))) > list(
            map(int, highestver[0].split("-", 2)[1].split("."))
        ):
            highestver = curriso
    if highestver:
        for curriso in list(isos):
            if curriso[0].split("-", 2)[1] != highestver[0].split("-", 2)[1]:
                isos.remove(curriso)
    return sorted(isos)


def _parse_sha256sums(body):
    """Parse a coreutils-style SHA256SUMS body into {filename: sha256_hex}."""
    checksums = {}
    if not body:
        return checksums
    for line in body.splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+[*]?(.+)$", line.strip())
        if m:
            checksums[m.group(2).strip()] = m.group(1).lower()
    return checksums


def _parse_release_sha256(body, wanted_path):
    """Return the SHA256 of *wanted_path* from a Debian Release/InRelease body."""
    if not body:
        return None
    for line in body.splitlines():
        parts = line.split()
        if len(parts) == 3 and len(parts[0]) == 64 and parts[2] == wanted_path:
            return parts[0].lower()
    return None


def _parse_debian_mini_isos(checksums, images_url):
    """Return [(relpath, url, sha256), …] for mini.iso entries in *checksums*."""
    isos = []
    for path, sha in checksums.items():
        rel = path.lstrip("./")
        if 'gtk' in rel:
            continue 
        if rel.endswith("mini.iso"):
            isos.append((rel, images_url + rel, sha))
    return sorted(isos)


# ── GPG verification ────────────────────────────────────────────────────────
def _gpg_base_cmd(gnupghome):
    """Return the common gpg argument prefix for a temporary keyring."""
    return [
        "gpg", "--batch", "--no-default-keyring",
        "--homedir", gnupghome,
        "--quiet", "--yes",
    ]


async def _gpg_import_key(gnupghome, key_text):
    """Import an ASCII-armored GPG public key into a temporary keyring.

    Returns True on success, False on failure.
    """
    cmd = _gpg_base_cmd(gnupghome) + ["--import"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate(input=key_text.encode())
    return proc.returncode == 0


async def _gpg_verify_inline(gnupghome, signed_text):
    """Verify a PGP clear-signed message.  Returns (ok, detail_str)."""
    cmd = _gpg_base_cmd(gnupghome) + ["--verify"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate(input=signed_text.encode())
    detail = stderr.decode(errors="replace").strip()
    return proc.returncode == 0, detail


async def _gpg_verify_detached(gnupghome, sig_text, data_text):
    """Verify a detached PGP signature.  Returns (ok, detail_str)."""
    # gpg --verify needs file paths for detached sigs, so use temp files.
    sig_path = os.path.join(gnupghome, "sig.asc")
    data_path = os.path.join(gnupghome, "data")
    with open(sig_path, "w") as f:
        f.write(sig_text)
    with open(data_path, "w") as f:
        f.write(data_text)
    cmd = _gpg_base_cmd(gnupghome) + ["--verify", sig_path, data_path]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    detail = stderr.decode(errors="replace").strip()
    return proc.returncode == 0, detail


async def _gpg_verify_detached_bytes(gnupghome, sig_bytes, data_bytes):
    """Verify a binary detached PGP signature.  Returns (ok, detail_str)."""
    sig_path = os.path.join(gnupghome, "sig.gpg")
    data_path = os.path.join(gnupghome, "data")
    with open(sig_path, "wb") as f:
        f.write(sig_bytes)
    with open(data_path, "wb") as f:
        f.write(data_bytes)
    cmd = _gpg_base_cmd(gnupghome) + ["--verify", sig_path, data_path]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    detail = stderr.decode(errors="replace").strip()
    return proc.returncode == 0, detail


def _sig_style_for(distro_cfg, major):
    """Return the effective sig_style string for a given major version."""
    overrides = distro_cfg.get("sig_style_overrides", {})
    return overrides.get(major, distro_cfg.get("sig_style", "none"))


def _extract_gpg_summary(detail):
    """Pull the one-line 'Good signature …' / 'BAD signature …' line."""
    for line in detail.splitlines():
        if "Good signature" in line or "BAD signature" in line:
            return line.strip()
    return detail.splitlines()[0].strip() if detail else ""


async def get_el_dl_info(session, distro_name, distro_cfg, version=None, arch=None):
    archmap = {
        'amd64': 'x86_64',
        'arm64': 'aarch64',
    }
    arch = archmap.get(arch, arch)
    base_url = distro_cfg["base_url"]
    dlinfo = DownloadInfo(distro=distro_name)
    
    if version and '.' in version:
        major = version.split('.')[0]
        minor = version.split('.')[1]
    elif version:
        major = version
        minor = None
    else:
        major = None
        minor = None
    if minor:
        raise ValueError(f"WARNING: minor version {minor} specified; only major versions are supported.")

    
    base_links = await fetch_links(session, base_url)
    majors = _parse_major_versions(base_links)
    if not majors:
        raise ValueError(f"WARNING: no major versions found for {distro_name} at {base_url}")
    if major == 'latest':
        major = majors[-1]
    if major and major in majors:
        majors = [major]
    elif major:
        raise ValueError(f"WARNING: requested major version {major} not found; using all majors.")
    
    iso_index_urls = [f"{base_url}{m}/isos/" for m in majors]
    gpg_key_urls = [
        distro_cfg["gpg_key_url_pattern"].format(major=m) for m in majors
    ]
    all_fetch_tasks = [fetch_links(session, u) for u in iso_index_urls] + [
        fetch_url(session, u) for u in gpg_key_urls
    ]
    all_results = await asyncio.gather(*all_fetch_tasks)
    iso_index_results = all_results[: len(majors)]
    gpg_key_results = all_results[len(majors) :]

    # Set up a temporary GPG home and import each major-version key.
    gnupghome = tempfile.mkdtemp(prefix="iso-gpg-")
    os.chmod(gnupghome, 0o700)
    try:
        key_imported = {}
        for major, key_body in zip(majors, gpg_key_results):
            if key_body and await _gpg_import_key(gnupghome, key_body):
                key_imported[major] = True
            else:
                key_imported[major] = False

        for major, iso_links in zip(majors, iso_index_results):
            point_releases = _parse_point_releases(base_links, major)
            if minor and minor in [p.split('.')[1] for p in point_releases]:
                point_releases = [p for p in point_releases if p.split('.')[1] == minor]
            latest = point_releases[-1] if point_releases else "unknown"
            sig_style = _sig_style_for(distro_cfg, major)

            dlinfo.release = latest

            arches = _parse_architectures(iso_links)
            if not arches:
                raise ValueError("No ISO architectures found.")
            if arch and arch in arches:
                arches = [arch]
            elif arch:
                raise ValueError(f"Requested architecture {arch} not found for {distro_name} {major}")

            arch_tasks = []
            for arch in arches:
                iso_dir = f"{base_url}{major}/isos/{arch}/"
                checksum_url = f"{iso_dir}CHECKSUM"
                tasks = [
                    fetch_links(session, iso_dir),
                    fetch_url(session, checksum_url),
                ]
                if sig_style == "detached":
                    tasks.append(fetch_url(session, f"{iso_dir}CHECKSUM.asc"))
                arch_tasks.append(asyncio.gather(*tasks))
            arch_results = await asyncio.gather(*arch_tasks)

            for arch, results in zip(arches, arch_results):
                iso_dir = f"{base_url}{major}/isos/{arch}/"
                dir_links = results[0]
                checksum_body = results[1]
                sig_body = results[2] if len(results) > 2 else None

                checksums = _parse_checksums(checksum_body)
                isos = _parse_el_isos(dir_links, iso_dir)

                # ── GPG verification of the CHECKSUM file ────────────
                if sig_style == "none" or not key_imported.get(major):
                    if sig_style == "none":
                        dlinfo.gpg_status = "unpublished"
                        gpg_status = "UNSIGNED (no signature published)"
                    else:
                        dlinfo.gpg_status = "unavailable"
                elif sig_style == "inline" and checksum_body:
                    ok, detail = await _gpg_verify_inline(
                        gnupghome, checksum_body
                    )
                    summary = _extract_gpg_summary(detail)
                    if not ok:
                        raise ValueError(f"GPG verification failed for {distro_name} {major} {arch}: {summary}")
                    dlinfo.gpg_status = "verified"
                    
                elif sig_style == "detached" and checksum_body and sig_body:
                    ok, detail = await _gpg_verify_detached(
                        gnupghome, sig_body, checksum_body
                    )
                    summary = _extract_gpg_summary(detail)
                    if not ok:
                        raise ValueError(f"GPG verification failed for {distro_name} {major} {arch}: {summary}")
                    dlinfo.gpg_status = "verified"
                else:
                    dlinfo.gpg_status = "missing"
                dlinfo.architecture = arch
                if not isos:
                    raise ValueError(f"No ISOs found for {distro_name} {major} {arch}")
                if len(isos) > 1:
                    raise ValueError(f"Multiple ISOs found for {distro_name} {major} {arch}; expected only one.")
                iso_name, iso_url = isos[0]
                dlinfo.iso_name = iso_name
                dlinfo.iso_url = iso_url
                dlinfo.iso_sha256 = checksums.get(iso_name, "n/a")
            return dlinfo
    finally:
        shutil.rmtree(gnupghome, ignore_errors=True)


async def get_ubuntu_dlinfo(session, cfg, version=None, arch=None):
    archmap = {
        'x86_64': 'amd64',
        'aarch64': 'arm64',
    }
    dlinfo = DownloadInfo(distro=cfg["name"])
    archextra = ''
    if '+' in arch:
        arch, archextra = arch.split('+', 1)
        archextra = '+' + archextra
    arch = archmap.get(arch, arch)

    name = cfg["name"]
    base_url = cfg["base_url"]

    base_links = await fetch_links(session, base_url)
    versions = _parse_ubuntu_versions(base_links)
    if not versions:
        raise ValueError("No versions found.")
    if version and version in versions:
        versions = [version]
    elif version:
        raise ValueError(f"Requested version {version} not found")

    gnupghome = tempfile.mkdtemp(prefix="iso-gpg-")
    os.chmod(gnupghome, 0o700)
    try:
        key_bodies = await asyncio.gather(
            *[fetch_url(session, u) for u in cfg["gpg_key_urls"]]
        )
        key_imported = False
        for key_body in key_bodies:
            if key_body and await _gpg_import_key(gnupghome, key_body):
                key_imported = True

        fetch_specs = []
        for ver in versions:
            for iterarch, url_pattern in cfg["sources"]:
                fetch_specs.append((ver, iterarch, url_pattern.format(ver=ver)))
        fetch_tasks = [
            asyncio.gather(
                fetch_links(session, iso_dir),
                fetch_bytes(session, f"{iso_dir}SHA256SUMS"),
                fetch_bytes(session, f"{iso_dir}SHA256SUMS.gpg"),
            )
            for _, _, iso_dir in fetch_specs
        ]
        fetch_results = await asyncio.gather(*fetch_tasks)

        by_version = {}
        for (ver, iterarch, iso_dir), res in zip(fetch_specs, fetch_results):
            by_version.setdefault(ver, []).append((iterarch, iso_dir, res))

        for ver in versions:
            point_releases = _parse_ubuntu_point_releases(base_links, ver)
            latest = point_releases[-1] if point_releases else ver
            dlinfo.release = latest
            found = False
            for iterarch, iso_dir, results in by_version[ver]:
                if arch and iterarch != arch:
                    continue
                dir_links, sums_bytes, sig_bytes = results
                isos = _parse_ubuntu_server_isos(dir_links, iterarch, iso_dir)
                if not isos:
                    continue
                isos = [(name, url) for name, url in isos if name.endswith(f"-{iterarch}{archextra}.iso")]
                if found:
                    raise ValueError(f"Multiple ISOs found for {name} {ver} {iterarch}; expected only one.")
                found = True

                sums_text = (
                    sums_bytes.decode("ascii", "replace") if sums_bytes else None
                )
                checksums = _parse_sha256sums(sums_text)

                # ── GPG verification of the SHA256SUMS file ──────────
                if not key_imported:
                    dlinfo.gpg_status = "unavailable"
                elif sums_bytes and sig_bytes:
                    ok, detail = await _gpg_verify_detached_bytes(
                        gnupghome, sig_bytes, sums_bytes
                    )
                    summary = _extract_gpg_summary(detail)
                    if not ok:
                        raise ValueError(f"GPG verification failed for {name} {ver} {iterarch}: {summary}")
                    dlinfo.gpg_status = "verified"
                else:
                    dlinfo.gpg_status = "missing"
                dlinfo.architecture = iterarch
                if len(isos) > 1:
                    print(repr(isos))
                    raise ValueError(f"Multiple ISOs found for {name} {ver} {iterarch}; expected only one.")
                iso_name, iso_url = isos[0]
                dlinfo.iso_name = iso_name
                dlinfo.iso_url = iso_url
                dlinfo.iso_sha256 = checksums.get(iso_name, "n/a")
            return dlinfo
    finally:
        shutil.rmtree(gnupghome, ignore_errors=True)


async def get_debian_dlinfo(session, cfg, version=None, arch=None):
    archmap = {
        'x86_64': 'amd64',
        'aarch64': 'arm64',
    }
    dlinfo = DownloadInfo(distro='debian')
    arch = archmap.get(arch, arch)
    name = cfg["name"]
    mirror = cfg["mirror"]

    gnupghome = tempfile.mkdtemp(prefix="iso-gpg-")
    os.chmod(gnupghome, 0o700)
    try:
        arches = cfg["arches"]
        if arch:
            arches = [x for x in arches if x == arch]
        if not arches:
            raise ValueError(f"Requested architecture {arch} not found for {name}")
        if version:
            if version == 'latest':
                version = cfg["suites"][-1][1]
        for codename, ver in cfg["suites"]:
            if version and version != ver and version != codename:
                continue
            key_url = cfg["archive_key_url_pattern"].format(ver=ver)
            inrelease_url = f"{mirror}dists/{codename}/InRelease"
            image_dirs = [
                f"{mirror}dists/{codename}/main/installer-{da}/current/images/"
                for da in arches
            ]

            # Fetch the signing key, InRelease and every arch SHA256SUMS at once.
            results = await asyncio.gather(
                fetch_url(session, key_url),
                fetch_url(session, inrelease_url),
                *[fetch_bytes(session, f"{d}SHA256SUMS") for d in image_dirs],
            )
            key_body, inrelease = results[0], results[1]
            sums_bytes_list = results[2:]

            # Import the release archive key and verify the InRelease signature.
            # Debian signs InRelease with several keys (current plus upcoming
            # releases); a Good signature from the imported archive key is
            # sufficient even though gpg exits non-zero on the unknown ones.
            key_imported = bool(key_body) and await _gpg_import_key(
                gnupghome, key_body
            )
            if key_imported and inrelease:
                _, detail = await _gpg_verify_inline(gnupghome, inrelease)
                sig_ok = (
                    "Good signature" in detail and "BAD signature" not in detail
                )
            else:
                sig_ok, detail = False, ""

            for deb_arch, images_url, sums_bytes in zip(
                arches, image_dirs, sums_bytes_list
            ):
                if arch and deb_arch != arch:
                    continue
                sums_text = (
                    sums_bytes.decode("ascii", "replace") if sums_bytes else None
                )
                checksums = _parse_sha256sums(sums_text)
                isos = _parse_debian_mini_isos(checksums, images_url)
                if not isos:
                    raise ValueError(f"No mini.iso found for {name} {ver} {deb_arch}")
                if len(isos) > 1:
                    raise ValueError(
                        f"Multiple mini.iso found for {name} {ver} {deb_arch}; expected only one."
                    )
                newname = f'debian-{ver}-{deb_arch}-mini.iso'
                
                dlinfo.release = ver
                dlinfo.architecture = deb_arch

                wanted = f"main/installer-{deb_arch}/current/images/SHA256SUMS"
                expected = _parse_release_sha256(inrelease, wanted)
                actual = (
                    hashlib.sha256(sums_bytes).hexdigest() if sums_bytes else None
                )
                if not key_imported:
                    dlinfo.gpg_status = "unavailable"
                elif not sig_ok:
                    raise ValueError(f"GPG verification failed for {name} {ver} {deb_arch}: {_extract_gpg_summary(detail)}")
                elif expected and actual and expected == actual:
                    dlinfo.gpg_status = "verified"
                else:
                    raise ValueError(f"GPG verification failed for {name} {ver} {deb_arch}: SHA256SUMS mismatch (expected {expected}, got {actual})")
                dlinfo.iso_name = newname
                dlinfo.iso_url = isos[0][1]
                dlinfo.iso_sha256 = isos[0][2]

            return dlinfo
    finally:
        shutil.rmtree(gnupghome, ignore_errors=True)


async def get_dlinfo(distspec):
    distparts = distspec.split("-", 2)
    if len(distparts) < 3:
        raise ValueError('Unable to parse distribution specifier; expected format: "<distro>-<version>-<arch>"')
    distname = distparts[0]
    async with aiohttp.ClientSession(timeout=REQUEST_TIMEOUT) as session:
        if distname in EL_DISTROS:
            return await get_el_dl_info(
                session,
                distname,
                EL_DISTROS[distname],
                distparts[1],
                distparts[2],
            )
        elif distname == "ubuntu":
            return await get_ubuntu_dlinfo(
                session, UBUNTU, distparts[1], distparts[2]
            )
        elif distname == "debian":
            return await get_debian_dlinfo(
                session, DEBIAN, distparts[1], distparts[2]
            )
        else:
            raise ValueError(f"Unsupported distribution: {distname}")

async def download_dist(distspec, dest_dir, progress_callback=None, dlinfo=None):
    if dlinfo is None:
        dlinfo = await get_dlinfo(distspec)
    if not dlinfo.iso_url:
        raise ValueError(f"No ISO URL found for {distspec}")
    iso_path = os.path.join(dest_dir, dlinfo.iso_name)
    async with aiohttp.ClientSession(timeout=DOWNLOAD_TIMEOUT) as session:
        async with session.get(dlinfo.iso_url) as resp:
            totalsize = int(resp.headers.get('Content-Length', 0))
            if resp.status != 200:
                raise ValueError(f"Failed to download ISO: {resp.status}")
            currsize = 0
            with open(iso_path, "wb") as f:
                while True:
                    chunk = await resp.content.read(1024 * 1024)
                    if not chunk:
                        break
                    currsize += len(chunk)
                    f.write(chunk)
                    if progress_callback:
                        await progress_callback(currsize, totalsize)
    return iso_path


def _format_bytes(num):
    """Return *num* bytes as a human-friendly string (e.g. '1.5 GiB')."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024 or unit == "TiB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{num} B"
        num /= 1024


def _format_duration(seconds):
    """Return *seconds* as a compact 'HH:MM:SS' / 'MM:SS' string."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


async def print_progress(currsize, totalsize):
    now = time.monotonic()
    # Reset timing when a new download begins (first call or size went backwards).
    if getattr(print_progress, "_start", None) is None or currsize < getattr(
        print_progress, "_last", 0
    ):
        print_progress._start = now
        print_progress._start_size = currsize
    print_progress._last = currsize

    elapsed = now - print_progress._start
    downloaded = currsize - print_progress._start_size
    rate = downloaded / elapsed if elapsed > 0 else 0
    speed = f" @ {_format_bytes(rate)}/s" if rate > 0 else ""

    if not totalsize:
        print(f"\r\033[KDownloaded {_format_bytes(currsize)}{speed}", end='', flush=True)
        return
    percent = (currsize / totalsize * 100)
    if rate > 0:
        eta = f", ETA {_format_duration((totalsize - currsize) / rate)}"
    else:
        eta = ""
    print(f"\r\033[KDownloaded {_format_bytes(currsize)} of {_format_bytes(totalsize)} ({percent:.2f}%){speed}{eta}", end='', flush=True)
    if currsize >= totalsize:
        print_progress._start = None  # reset for the next download
        print()  # New line after completion

async def async_main():
    from pprint import pprint
    
    distname = sys.argv[1] if len(sys.argv) > 1 else None
    if not distname:
        print("Usage: rocky_iso_urls.py <distro_name>", file=sys.stderr)
        sys.exit(1)
    dlinfo = await get_dlinfo(distname)
    pprint(dlinfo)
    tmpdir = tempfile.mkdtemp(prefix="iso-download-")

    iso_path = await download_dist(distname, tmpdir, print_progress, dlinfo=dlinfo)
    print(f"\nDownloaded ISO to: {iso_path}")


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()

