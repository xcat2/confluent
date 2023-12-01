#!/usr/bin/bash
# remove online repos
grep -lE "baseurl=https?://download.opensuse.org" /etc/zypp/repos.d/*repo | xargs rm --
