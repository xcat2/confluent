Ansible playbooks ending in .yml or .yaml that are placed into this directory will be executed at the
appropriate phase of the install process.

The 'hosts' may be omitted, and if included will be ignored, replaced with the host that is specifically
requesting the playbooks be executed.

Also, the playbooks will be executed on the deployment server. Hence it may be slower in aggregate than
running content under scripts/ which ask much less of the deployment server

Here is an example of what a playbook would look like broadly:

- name: Example
  gather_facts: no
  tasks:
       - name: Example1
         lineinfile:
           path: /etc/hosts
           line: 1.2.3.4 test1
           create: yes
       - name: Example2
         lineinfile:
           path: /etc/hosts
           line: 1.2.3.5 test2
           create: yes

