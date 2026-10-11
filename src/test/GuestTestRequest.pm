package GuestTestRequest;

use strict;
use warnings;

use PVE::API2;
use PVE::HTTPServer;

# The helper uses bless because new requires socket, lockfh, and lockfile.
sub guest_request {
    my ($rpcenv, $user, $method, $vmid, $operation, $params) = @_;

    my $server = bless({ rpcenv => $rpcenv }, 'PVE::HTTPServer');
    my $auth = { userid => $user };
    $auth->{api_token} = 1 if $user =~ m/!/;

    return $server->rest_handler(
        '127.0.0.1', $method, "/nodes/localhost/qemu/$vmid/$operation", $auth, $params,
    );
}

1;
