#!/bin/bash
# Assemble the nightly bundle for one target: the packages, repository
# metadata so the directory also works as a dnf/zypper/apt repository, and
# an INSTALL.txt. Produces confluent-nightly-<target>.tar.gz in <outdir>.
#
# Usage: mkbundle.sh <target> <version> <outdir> <package file>...
#   target is <el9|el10|suse16|noble|resolute>-<arch>
set -e

TARGET=$1
VERSION=$2
OUTDIR=$(readlink -f "$3")
shift 3

NAME=confluent-nightly-$TARGET
DIR=$OUTDIR/$NAME
REPO=${GITHUB_REPOSITORY:-xcat2/confluent}
SHA=${GITHUB_SHA:-$(git rev-parse HEAD)}
rm -rf "$DIR"
mkdir -p "$DIR"
cp "$@" "$DIR"/
echo "$VERSION" > "$DIR"/VERSION

cat > "$DIR"/INSTALL.txt <<EOF
confluent nightly $VERSION ($TARGET)

Unofficial development build of https://github.com/$REPO
commit $SHA. Packages are unsigned. Not meant for production.

EOF

case "$TARGET" in
el*)
    createrepo_c -q "$DIR"
    cat >> "$DIR"/INSTALL.txt <<EOF
Dependencies come from the distribution plus EPEL and CRB:

    dnf install epel-release
    crb enable

Install everything:

    dnf install ./$NAME/*.rpm

or only some of it, using the directory as a repository:

    dnf install --repofrompath=confluent-nightly,\$PWD/$NAME \\
        --setopt=confluent-nightly.gpgcheck=0 confluent_server
EOF
    ;;
suse*)
    createrepo_c -q "$DIR"
    cat >> "$DIR"/INSTALL.txt <<EOF
Install everything:

    zypper --no-gpg-checks install --allow-unsigned-rpm ./$NAME/*.rpm

or only some of it, using the directory as a repository:

    zypper addrepo --no-gpgcheck \$PWD/$NAME confluent-nightly
    zypper install confluent_server
EOF
    ;;
noble*|resolute*)
    (cd "$DIR" && dpkg-scanpackages --multiversion . /dev/null 2> /dev/null | gzip -9 > Packages.gz)
    cat >> "$DIR"/INSTALL.txt <<EOF
Install everything:

    apt install ./$NAME/*.deb

or only some of it, using the directory as a repository:

    echo "deb [trusted=yes] file:\$PWD/$NAME ./" > /etc/apt/sources.list.d/confluent-nightly.list
    apt update && apt install confluent-server
EOF
    ;;
*)
    echo "unknown target $TARGET" >&2
    exit 1
    ;;
esac

cat >> "$DIR"/INSTALL.txt <<EOF

The bundle carries the osdeploy support for both x86_64 and aarch64
deployment targets. Genesis (confluent-genesis-*) is not built yet.
EOF

tar -C "$OUTDIR" -czf "$OUTDIR/$NAME.tar.gz" "$NAME"
rm -rf "$DIR"
echo "$OUTDIR/$NAME.tar.gz"
