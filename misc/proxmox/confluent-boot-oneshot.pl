#!/usr/bin/perl
# Proxmox VE hookscript: makes a confluent `nodesetboot` without -p one-time.
#
# Install on every PVE node and attach to each VM confluent manages:
#
#   cp confluent-boot-oneshot.pl /var/lib/vz/snippets/ && chmod 755 $_
#   qm set <vmid> --hookscript local:snippets/confluent-boot-oneshot.pl
#
# confluent records the order to restore as "confluent-boot-restore: <order|none>"
# in the VM description; after the next start this restores it and drops the line.
# The restored order applies from the next cold start.
use strict;
use warnings;

my ($vmid, $phase) = @ARGV;
exit 0 unless defined $phase;

# Hooks run inside the task holding the config lock: keep this path cheap
# (no PVE modules) and do the restore detached.
if ($phase eq 'post-start') {
    # Description lines are '#' comments, ':' percent-encoded.
    open(my $fh, '<', "/etc/pve/qemu-server/$vmid.conf") or exit 0;
    my $pending = grep { /^#confluent-boot-restore(?::|%3A) /i } <$fh>;
    close($fh);
    exit 0 unless $pending;
    # Not a fork: a child would inherit the start task's lock and output pipe.
    exec('systemd-run', '--no-block', '--collect', '--quiet',
         "--unit=confluent-boot-restore-$vmid-" . time(),
         '/usr/bin/perl', $0, $vmid, 'confluent-restore')
        or die "confluent-boot-oneshot: systemd-run: $!\n";
}

exit 0 unless $phase eq 'confluent-restore';
require PVE::QemuConfig;
for my $try (1 .. 30) {
    my $conf = PVE::QemuConfig->load_config($vmid);
    my $desc = $conf->{description} // '';
    exit 0 unless $desc =~ /^confluent-boot-restore: (\S+)\s*$/m;
    my $restore = $1;
    $desc =~ s/^confluent-boot-restore: .*(?:\n|$)//m;
    my @cmd = ('qm', 'set', $vmid, '--description', $desc);
    push @cmd, $restore eq 'none' ? ('--delete', 'boot') : ('--boot', $restore);
    exit 0 if system(@cmd) == 0;
    sleep 2;
}
die "confluent-boot-oneshot: could not restore the boot order of $vmid\n";
