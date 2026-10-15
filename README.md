# Confluent

[![CI](https://github.com/xcat2/confluent/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/xcat2/confluent/actions/workflows/ci.yml?query=branch%3Amaster)
[![Nightly](https://github.com/xcat2/confluent/actions/workflows/nightly.yml/badge.svg?branch=master)](https://github.com/xcat2/confluent/actions/workflows/nightly.yml?query=branch%3Amaster)
[![Release](https://img.shields.io/github/v/release/xcat2/confluent?sort=semver)](https://github.com/xcat2/confluent/releases/latest)
[![Docs](https://img.shields.io/badge/docs-confluent--docs-blueviolet?logo=data:image/svg%2Bxml;base64,PHN2ZyBmaWxsPSJ3aGl0ZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiI%2BPHBhdGggZD0iTTAgMS43NUEuNzUuNzUgMCAwIDEgLjc1IDFoNC4yNTNjMS4yMjcgMCAyLjMxNy41OSAzIDEuNTAxQTMuNzQzIDMuNzQzIDAgMCAxIDExLjAwNiAxaDQuMjQ1YS43NS43NSAwIDAgMSAuNzUuNzV2MTAuNWEuNzUuNzUgMCAwIDEtLjc1Ljc1aC00LjUwN2EyLjI1IDIuMjUgMCAwIDAtMS41OTEuNjU5bC0uNjIyLjYyMWEuNzUuNzUgMCAwIDEtMS4wNiAwbC0uNjIyLS42MjFBMi4yNSAyLjI1IDAgMCAwIDUuMjU4IDEzSC43NWEuNzUuNzUgMCAwIDEtLjc1LS43NVptNy4yNTEgMTAuMzI0LjAwNC01LjA3My0uMDAyLTIuMjUzQTIuMjUgMi4yNSAwIDAgMCA1LjAwMyAyLjVIMS41djloMy43NTdhMy43NSAzLjc1IDAgMCAxIDEuOTk0LjU3NFpNOC43NTUgNC43NWwtLjAwNCA3LjMyMmEzLjc1MiAzLjc1MiAwIDAgMSAxLjk5Mi0uNTcySDE0LjV2LTloLTMuNDk1YTIuMjUgMi4yNSAwIDAgMC0yLjI1IDIuMjVaIi8%2BPC9zdmc%2B)](https://xcat2.github.io/confluent-docs/)
![Python 3](https://img.shields.io/badge/python-3-3776ab?logo=python&logoColor=white)
[![License](https://img.shields.io/github/license/xcat2/confluent)](LICENSE)

Confluent is a software package to handle essential bootstrap and operation of scale-out server configurations.
It supports stateful and stateless deployments for various operating systems.

Check [this page](https://xcat2.github.io/confluent-docs/) for a more detailed list of features.

Confluent is the modern successor of [xCAT](https://github.com/xcat2/xcat-core).
If you're coming from xCAT, check out [this comparison](https://xcat2.github.io/confluent-docs/miscellaneous/confluentvxcat/).

# Documentation

Confluent documentation is hosted on: https://xcat2.github.io/confluent-docs/

# Download

Get the latest version from: https://xcat2.github.io/confluent-docs/downloads/

Check release notes on: https://xcat2.github.io/confluent-docs/release_notes/

# Open Source License

Confluent is made available under the Apache 2.0 license: https://opensource.org/license/apache-2-0

# Developers

Want to help? Submit a [Pull Request](https://github.com/xcat2/confluent/pulls).

## Versioning and releases

The top-level `VERSION` file names the release the current branch is working toward. Build scripts
call `./mkversion`, which turns it into the version stamped on packages: the tag itself on a release
tag (`4.0.1`), otherwise a development version (`4.0.1~dev5+gdeadbee`). Packages sort it before the
release it leads up to. Only `setup.py` gets the PEP 440 spelling, `4.0.1.dev5+gdeadbee`.

`mkversion` also derives a version from the newest tag reachable from HEAD and uses whichever is
higher, so forgetting to bump `VERSION` after tagging the current branch cannot walk the version
backwards. Staying ahead of tags on *other* branches is what `VERSION` itself is for: patch releases
are tagged on release branches, which master never sees.

Cutting a new series:

1. Land the release commit on master and tag `X.Y.0` there.
2. Create branch `X.Y` from that tag; it inherits `VERSION=X.Y.0`.
3. Only then bump `VERSION` on master. Doing it before step 2 leaves the release branch on the
   wrong series.

Patch releases land on branch `X.Y` and are tagged `X.Y.Z` there; no `VERSION` edit is needed.

## Nightly builds

`.github/workflows/nightly.yml` builds the rpms (EL9, EL10, SUSE 16) and debs (Ubuntu 24.04, 26.04)
for x86_64 and aarch64 every night that something changed, installs each set on a clean container,
and publishes them as the `nightly` pre-release. Every bundle there holds all packages for one
target and an `INSTALL.txt`. Pull requests that touch the packaging run the same build and tests
without publishing. Genesis is not built there yet.
