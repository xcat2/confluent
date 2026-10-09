# Proxmox VE virtual machines in confluent

The `proxmox` hardware management plugin lets confluent manage Proxmox VE
(8 and 9) QEMU virtual machines with its usual commands. Each VM is a
confluent node; the Proxmox API stands in for its BMC.

## Defining the nodes

The node name is the VM name in Proxmox. VM names must be unique across
the cluster; templates are ignored.

    nodegroupdefine pvevms hardwaremanagement.method=proxmox \
        hardwaremanagement.manager=pve1.example.com \
        secret.hardwaremanagementuser=confluent@pve \
        secret.hardwaremanagementpassword=...
    nodedefine vm1,vm2 groups=pvevms

`hardwaremanagement.manager` is a node of the Proxmox cluster; any node
answers for every VM in the cluster.

The manager's certificate is pinned on first use. When the manager is not
itself a confluent node, its pin is stored on the VM's node
(`pubkeys.tls_hardwaremanager`).

The login can be a Proxmox user with a password, or an API token
(`user@realm!tokenid` as the user, the token secret as the password). A
token cannot open the graphical console, because the VNC proxy only
accepts a ticket cookie. Users with two-factor authentication cannot be
used.

## Proxmox permissions

Grant a role on the VMs (on a pool, or on `/vms`). The base role:

    pveum role add Confluent --privs VM.Audit,VM.PowerMgmt,VM.Config.Options,VM.Config.Disk,VM.Console

| Command | Needs, beyond the base role |
|---|---|
| nodepower, nodesetboot, nodeconsole, nodeinventory | nothing |
