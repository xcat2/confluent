FROM almalinux:8
RUN ["yum", "-y","update"]
RUN ["yum", "-y","install","gcc","make","rpm-build","python3-devel","python3-setuptools","createrepo","python3", "perl", "perl-DBI", "perl-JSON", "perl-Net-DNS", "perl-DB_File", "perl-XML-LibXML", "rpm-sign", "git", "fuse-devel","libcurl-devel"]
ADD rpmmacro /root/.rpmmacros
ADD buildpackages.sh /bin/
#VOLUME ["/rpms", "/srpms"]
CMD ["/bin/bash","/bin/buildpackages.sh"]

