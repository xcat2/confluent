for package in /srpms/*; do
        rpmbuild --rebuild $package
done
find ~/rpmbuild/RPMS -type f -exec cp {} /rpms/ \;


