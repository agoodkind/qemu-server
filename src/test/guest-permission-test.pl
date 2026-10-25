#!/usr/bin/perl

use strict;
use warnings;

use lib qw(.. .);

use HTTP::Status qw(:constants);

use PVE::RPCEnvironment;

use GuestTestRequest;

my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'guest-permission-test.cfg');

my $vmid = 100;

my $guest_requests = {
    exec => {
        method => 'POST',
        operation => 'exec',
        params => { command => ['true'] },
        privilege => 'VM.Guest.Exec',
    },
    exec_status => {
        method => 'GET',
        operation => 'exec-status',
        params => { pid => 1 },
        privilege => 'VM.Guest.Exec',
    },
    exec_ack => {
        method => 'POST',
        operation => 'exec-ack',
        params => { pid => 1 },
        privilege => 'VM.Guest.Exec',
    },
    file_write => {
        method => 'POST',
        operation => 'file-write',
        params => { file => '/tmp/guest-permission-test', content => '' },
        privilege => 'VM.Guest.FileWrite',
    },
    file_read => {
        method => 'GET',
        operation => 'file-read',
        params => { file => '/tmp/guest-permission-test' },
        privilege => 'VM.Guest.FileRead',
    },
};

# Each token role has one guest privilege. The owning user has all three.
my $guest_tokens = {
    'erin@pve!exec' => 'VM.Guest.Exec',
    'erin@pve!read' => 'VM.Guest.FileRead',
    'erin@pve!write' => 'VM.Guest.FileWrite',
};

# The methods return status 500 after authorization in this test without VM configuration.
sub request_is_authorized {
    my ($name, $user, $request_vmid) = @_;

    my $request = $guest_requests->{$name};
    my $response = GuestTestRequest::guest_request(
        $rpcenv,
        $user,
        $request->{method},
        $request_vmid,
        $request->{operation},
        { %{ $request->{params} } },
    );
    my $status = $response->{status};
    my $message = $response->{message} // '';

    return 1 if $status == HTTP_INTERNAL_SERVER_ERROR;
    return 1 if $name eq 'exec_ack' && $status == HTTP_OK;

    my $privilege = $request->{privilege};
    return 0
        if $status == HTTP_FORBIDDEN
        && $message =~ m/Permission check failed \(\/vms\/$request_vmid, \Q$privilege\E\)/;

    die "request for $name as $user returned unexpected HTTP status $status with message"
        . " $message\n";
}

for my $name (sort keys %$guest_requests) {
    my $privilege = $guest_requests->{$name}->{privilege};

    for my $token (sort keys %$guest_tokens) {
        my $allowed = request_is_authorized($name, $token, $vmid);
        my $should_pass = $guest_tokens->{$token} eq $privilege;
        die "token $token was rejected for $name\n" if $should_pass && !$allowed;
        die "token $token passed for $name\n" if !$should_pass && $allowed;
        print "GUEST PERM:$name:$token:" . ($allowed ? 'allowed' : 'denied') . "\n";
    }

    for my $user ('erin@pve', 'root@pam') {
        die "user $user was rejected for $name\n" if !request_is_authorized($name, $user, $vmid);
    }
    # VM.Audit and VM.GuestAgent privileges do not authorize these methods.
    for my $user ('dave@pve', 'frank@pve') {
        die "user $user passed for $name\n" if request_is_authorized($name, $user, $vmid);
    }
    # The token ACLs do not grant privileges on VM 101.
    for my $token (sort keys %$guest_tokens) {
        die "token $token passed for $name on VM 101\n"
            if request_is_authorized($name, $token, 101);
    }
}

print "all tests passed\n";

exit(0);
