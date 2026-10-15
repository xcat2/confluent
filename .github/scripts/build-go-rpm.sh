#!/bin/bash
# Build the rpm of one of the Go helpers confluent runs but keeps in separate
# repositories (browserfs, vinz), for the native architecture only.
#
# Mirrors the buildrpm script in those repositories, which needs git tags for
# its version. They carry none yet, so fall back to 0~dev<commits>+g<hash>,
# which sorts below any tagged release.
#
# Usage: build-go-rpm.sh <name> <git-url> [ref]
set -e

NAME=$1
URL=$2
REF=${3:-HEAD}
WORK=$(mktemp -d)

git clone -q "$URL" "$WORK/$NAME"
cd "$WORK/$NAME"
git checkout -q "$REF"
if desc=$(git describe 2>/dev/null); then
    VERSION=${desc%%-*}
    NUMCOMMITS=$(echo "$desc" | cut -d- -f2)
    if [ "$NUMCOMMITS" != "$VERSION" ]; then
        VERSION=$(echo "$VERSION" | awk -F. -v OFS=. '{$NF=$NF+1; print}')
        VERSION=$VERSION~dev$NUMCOMMITS+$(echo "$desc" | cut -d- -f3)
    fi
else
    VERSION=0~dev$(git rev-list --count HEAD)+g$(git rev-parse --short HEAD)
fi
echo "$NAME $VERSION ($(git rev-parse HEAD))"

mkdir -p ~/rpmbuild/SOURCES
(cd .. && tar cf ~/rpmbuild/SOURCES/confluent-$NAME.tar --exclude=.git "$NAME")
sed -e "s/#VERSION#/$VERSION/" $NAME.spec.tmpl > $NAME.spec
rpmbuild -ba $NAME.spec
