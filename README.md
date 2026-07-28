# Confluent

![Python 3](https://img.shields.io/badge/python-3-blue.svg) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/xcat2/confluent/blob/master/LICENSE)

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
tag (`4.0.1`), otherwise a development version (`4.0.1.dev5+gdeadbee`, or `4.0.1~dev5+gdeadbee` for
the packages that have no `setup.py`).

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
