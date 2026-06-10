FROM ubuntu:noble
ADD stdeb.patch /tmp/
ADD buildapt.sh /bin/
ADD distributions.tmpl /bin/
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "reprepro", "python3-stdeb", "gnupg-agent", "devscripts", "debhelper", "libsoap-lite-perl", "libdbi-perl", "quilt", "git", "python3-pyparsing", "python3-netifaces", "dh-python", "libjson-perl", "pandoc", "alien", "gcc", "make", "alien"]
RUN ["mkdir", "-p", "/sources/git/"]
RUN ["mkdir", "-p", "/debs/"]
RUN ["mkdir", "-p", "/apt/"]
RUN ["bash", "-c", "patch -p1 < /tmp/stdeb.patch"]
CMD ["/bin/bash", "/bin/buildapt.sh"]

