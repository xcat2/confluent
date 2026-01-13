FROM almalinux:10
RUN ["yum", "-y","update"]
RUN ["yum", "-y","install","gcc","make","rpm-build","python3-devel","python3-setuptools","createrepo","python3", "perl", "perl-DBI", "perl-JSON", "perl-XML-LibXML", "pinentry-tty", "rpm-sign", "git", "golang"]
ADD rpmmacro /root/.rpmmacros
ADD buildpackages.sh /bin/
#VOLUME ["/rpms", "/srpms"]
CMD ["/bin/bash","/bin/buildpackages.sh"]

