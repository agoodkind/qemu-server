#!/usr/bin/perl

use strict;
use warnings;

use lib qw(..);

use PVE::API2::Qemu;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => 'guest-permission-test.cfg');

my $vmid = 100;

my $guest_methods = {
    exec => { method => 'POST', path => '{vmid}/exec', privilege => 'VM.Guest.Exec' },
    exec_status => {
        method => 'GET',
        path => '{vmid}/exec-status',
        privilege => 'VM.Guest.Exec',
    },
    file_write => {
        method => 'POST',
        path => '{vmid}/file-write',
        privilege => 'VM.Guest.FileWrite',
    },
    file_read => {
        method => 'GET',
        path => '{vmid}/file-read',
        privilege => 'VM.Guest.FileRead',
    },
};

# Each token role has one guest privilege. The owning user has all three.
my $guest_tokens = {
    'erin@pve!exec' => 'VM.Guest.Exec',
    'erin@pve!read' => 'VM.Guest.FileRead',
    'erin@pve!write' => 'VM.Guest.FileWrite',
};

for my $name (sort keys %$guest_methods) {
    my $expected = $guest_methods->{$name};

    my $info = PVE::API2::Qemu->map_method_by_name($name);
    die "method $name is not registered\n" if !$info;
    die "method $name has unexpected path $info->{path}\n"
        if $info->{path} ne $expected->{path};
    die "method $name has unexpected HTTP method $info->{method}\n"
        if $info->{method} ne $expected->{method};

    my $check = $info->{permissions}->{check};
    die "method $name does not use a perm check on /vms/{vmid}\n"
        if $check->[0] ne 'perm' || $check->[1] ne '/vms/{vmid}';
    my $privileges = $check->[2];
    die "method $name checks privileges @$privileges instead of $expected->{privilege}\n"
        if "@$privileges" ne $expected->{privilege};

    for my $token (sort keys %$guest_tokens) {
        my $allowed = $rpcenv->check_vm_perm($token, $vmid, undef, $privileges, 0, 1);
        my $should_pass = $guest_tokens->{$token} eq $expected->{privilege};
        die "token $token was rejected for $name\n" if $should_pass && !$allowed;
        die "token $token passed for $name\n" if !$should_pass && $allowed;
        print "GUEST PERM:$name:$token:" . ($allowed ? 'allowed' : 'denied') . "\n";
    }

    for my $user ('erin@pve', 'root@pam') {
        die "user $user was rejected for $name\n"
            if !$rpcenv->check_vm_perm($user, $vmid, undef, $privileges, 0, 1);
    }
    # VM.Audit and VM.GuestAgent privileges do not authorize these methods.
    for my $user ('dave@pve', 'frank@pve') {
        die "user $user passed for $name\n"
            if $rpcenv->check_vm_perm($user, $vmid, undef, $privileges, 0, 1);
    }
    # The token ACLs do not grant privileges on VM 101.
    for my $token (sort keys %$guest_tokens) {
        die "token $token passed for $name on VM 101\n"
            if $rpcenv->check_vm_perm($token, 101, undef, $privileges, 0, 1);
    }
}

print "all tests passed\n";

exit(0);
