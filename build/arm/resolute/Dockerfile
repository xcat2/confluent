FROM ubuntu:resolute
ADD stdeb.patch /tmp/
ADD buildapt.sh /bin/
ADD distributions.tmpl /bin/
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "reprepro", "python3-stdeb", "gnupg-agent", "devscripts", "debhelper", "libsoap-lite-perl", "libdbi-perl", "quilt", "git", "python3-pyparsing", "python3-dnspython", "python3-netifaces", "python3-asyncssh", "dh-python", "libjson-perl", "pandoc", "alien", "gcc", "make"]
RUN ["mkdir", "-p", "/sources/git/"]
RUN ["mkdir", "-p", "/debs/"]
RUN ["mkdir", "-p", "/apt/"]
CMD ["/bin/bash", "/bin/buildapt.sh"]

