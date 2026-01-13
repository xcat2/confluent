FROM almalinux:9
RUN ["yum", "-y","update"]
RUN ["yum", "-y","install","gcc","make","rpm-build","python3-devel","python3-setuptools","createrepo","python3", "perl", "perl-DBI", "perl-JSON", "perl-Net-DNS", "perl-DB_File", "perl-XML-LibXML", "pinentry-tty", "rpm-sign", "epel-release", "git"]
RUN ["crb", "enable"]
RUN ["yum", "-y","install","fuse-devel","libcurl-devel"]
ADD rpmmacro /root/.rpmmacros
ADD buildpackages.sh /bin/
#VOLUME ["/rpms", "/srpms"]
CMD ["/bin/bash","/bin/buildpackages.sh"]

