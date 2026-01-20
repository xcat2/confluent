FROM almalinux:10
VOLUME /var/lib/confluent
VOLUME /var/run/confluent
VOLUME /etc/confluent
VOLUME /var/lib/tftpboot
ENV EMBEDHTTP=1
ENV EMBEDTFTP=0
RUN ["yum", "-y", "update"]
RUN ["rpm", "-ivh", "https://hpc.lenovo.com/yum/latest/el10/x86_64/lenovo-hpc-yum-1-1.x86_64.rpm"]
RUN ["yum", "-y", "install", "lenovo-confluent", "tftp-server", "openssh-clients", "openssl", "vim-enhanced", "iproute", "policycoreutils", "selinux-policy-targeted", "device-mapper"]
RUN ["chown", "-r", "root", "/etc/confluent"]
ADD runconfluent.sh /bin/
CMD ["/bin/bash", "/bin/runconfluent.sh"]

