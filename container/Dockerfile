FROM almalinux:9
RUN ["yum", "-y", "update"]
RUN ["rpm", "-ivh", "https://hpc.lenovo.com/yum/latest/el9/x86_64/lenovo-hpc-yum-1-1.x86_64.rpm"]
RUN ["yum", "-y", "install", "lenovo-confluent", "tftp-server", "openssh-clients", "openssl", "vim-enhanced", "iproute"]
RUN ["chown", "-r", "root", "/etc/confluent"]
ADD runconfluent.sh /bin/
CMD ["/bin/bash", "/bin/runconfluent.sh"]

