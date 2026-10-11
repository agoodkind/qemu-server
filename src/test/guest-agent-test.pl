#!/usr/bin/perl -T

# qemu-ga runs commands on the test host as the test user.

use strict;
use warnings;

use File::Basename qw(basename);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX;
use Time::HiRes qw();

use lib qw(.. .);

use HTTP::Status qw(:constants);

use PVE::API2::Qemu::Guest;
use PVE::ProcFSTools;
use PVE::QemuConfig;
use PVE::QemuServer::Helpers;
use PVE::RPCEnvironment;
use PVE::UPID;

use GuestTestRequest;

my $VMID = 100;
my $OTHER_VMID = 101;
my $OWNER_USER = 'erin@pve';
my $EXEC_USER = 'erin@pve!exec';
my $READ_USER = 'erin@pve!read';
my $WRITE_USER = 'erin@pve!write';
my $QEMU_GA = '/usr/sbin/qemu-ga';
my $SOCKET_DIRECTORY = '/var/run/qemu-server';
my $AGENT_START_SECONDS = 30;
my $POLL_SECONDS = 60;
my $EXEC_TIMEOUT_ABOVE_MAXIMUM = 3601;
my $EXEC_OUTPUT_LIMIT = PVE::API2::Qemu::Guest::exec_output_limit();
my $FILE_READ_LIMIT = PVE::API2::Qemu::Guest::file_read_limit();

my $vm_config = { agent => '1' };

{
    no warnings qw(redefine once);
    *PVE::QemuConfig::load_config = sub { return $vm_config };
    *PVE::QemuServer::Helpers::vm_running_locally = sub { return 1 };
    *PVE::ProcFSTools::read_proc_starttime = sub { return 1 };
}

# The UTF-8 layer prevents Wide character in print warnings for non-ASCII qemu-ga errors.
binmode(STDOUT, ':encoding(UTF-8)');

$ENV{PATH} = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

die "qemu-ga is not executable at $QEMU_GA\n" if !-x $QEMU_GA;

my $work_directory = tempdir(CLEANUP => 1);
die "unexpected temporary directory\n" if $work_directory !~ m/\A(\S+)\z/;
$work_directory = $1;

# fork_worker writes the task log below this directory, which exists on a node.
make_path('/var/log/pve/tasks', $SOCKET_DIRECTORY);

my $socket_path = "$SOCKET_DIRECTORY/$VMID.qga";

sub start_agent {
    unlink($socket_path);
    my $pid = fork() // die "fork failed: $!\n";
    if (!$pid) {
        exec {$QEMU_GA} (
            $QEMU_GA,
            '--method', 'unix-listen',
            '--path', $socket_path,
            '--statedir', $work_directory,
            '--pidfile', "$work_directory/qemu-ga.pid",
            '--logfile', "$work_directory/qemu-ga.log",
        ) or POSIX::_exit(127);
    }

    my $deadline = Time::HiRes::time() + $AGENT_START_SECONDS;
    while (!-S $socket_path) {
        die "qemu-ga did not create socket $socket_path within 30 seconds\n"
            if Time::HiRes::time() >= $deadline;
        die "qemu-ga exited before creating its socket\n" if waitpid($pid, WNOHANG) == $pid;
        Time::HiRes::sleep(0.1);
    }
    return $pid;
}

sub stop_agent {
    my ($pid) = @_;

    kill('TERM', $pid);
    waitpid($pid, 0);
}

my $agent_pid = start_agent();
END {
    if ($agent_pid) {
        my $exit_status = $?;
        stop_agent($agent_pid);
        $? = $exit_status;
    }
}

my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'guest-permission-test.cfg');

my $test_start = time();
my $started_count = 0;

sub call_guest {
    my ($user, $method, $vmid, $operation, $params) = @_;

    my $response =
        GuestTestRequest::guest_request($rpcenv, $user, $method, $vmid, $operation, $params);
    die $response->{message} if $response->{status} != HTTP_OK;
    return $response->{data};
}

sub call_exec {
    my ($param) = @_;

    my $result = call_guest($EXEC_USER, 'POST', $VMID, 'exec', $param);
    $started_count++;
    return $result->{pid};
}

sub call_exec_status {
    my ($user, $vmid, $pid) = @_;

    return call_guest($user, 'GET', $vmid, 'exec-status', { pid => $pid });
}

sub call_file_write {
    my ($file, $content) = @_;

    return call_guest(
        $WRITE_USER, 'POST', $VMID, 'file-write', { file => $file, content => $content },
    );
}

sub call_file_read {
    my ($file) = @_;

    return call_guest($READ_USER, 'GET', $VMID, 'file-read', { file => $file });
}

sub wait_for_exit {
    my ($pid) = @_;

    my $deadline = Time::HiRes::time() + $POLL_SECONDS;
    while (Time::HiRes::time() < $deadline) {
        my $status = call_exec_status($EXEC_USER, $VMID, $pid);
        if ($status->{exited}) {
            $status->{stdout} = decode_base64($status->{'out-data'});
            $status->{stderr} = decode_base64($status->{'err-data'});
            return $status;
        }
        Time::HiRes::sleep(0.05);
    }
    die "exec-status did not report command $pid as exited within 60 seconds\n";
}

sub run_command {
    my ($param) = @_;

    return wait_for_exit(call_exec($param));
}

sub check_equal {
    my ($label, $got, $expected) = @_;

    $got //= 'undefined';
    die "unexpected result for $label\nneed '$expected'\ngot '$got'\n" if $got ne $expected;
    print "OK:$label\n";
}

sub check_dies {
    my ($label, $pattern, $code) = @_;

    eval { $code->() };
    my $error = $@;
    die "the tested code did not raise an error for $label\n" if !$error;
    die "the error for $label does not match the expected pattern: $error"
        if $error !~ $pattern;
    print "OK:$label:$error";
}

my $input_status = run_command({
    command => ['sh', '-c', 'cat; echo problem >&2; exit 3'],
    'input-data' => encode_base64("first line\nsecond line\n", ''),
});
check_equal('exec-status returns exit code 3', $input_status->{exitcode}, 3);
check_equal(
    'exec-status returns input-data as standard output',
    $input_status->{stdout},
    "first line\nsecond line\n",
);
check_equal('exec-status returns standard error', $input_status->{stderr}, "problem\n");
die "exec-status reported timed-out for a command that exited within its timeout\n"
    if $input_status->{'timed-out'};

my $no_input_status = run_command({ command => ['cat'] });
check_equal('cat exits with code 0 without input-data', $no_input_status->{exitcode}, 0);
check_equal(
    'cat produces no standard output without input-data', $no_input_status->{stdout}, '',
);

my $signal_status = run_command({ command => ['sh', '-c', 'kill -KILL $$'] });
check_equal('exec-status returns exit code 137 after KILL', $signal_status->{exitcode}, 128 + 9);

my $large_status = run_command({
    command => ['head', '-c', $EXEC_OUTPUT_LIMIT + 1, '/dev/zero'],
});
check_equal(
    'exec-status returns 1048576 bytes of standard output',
    length($large_status->{stdout}),
    $EXEC_OUTPUT_LIMIT,
);
check_equal('out-truncated', $large_status->{'out-truncated'}, 1);
die "exec-status reported unexpected err-truncated\n" if $large_status->{'err-truncated'};

# The shell uses exec because the termination check must inspect sleep's process ID.
my $timeout_status = run_command({
    command => ['sh', '-c', 'echo $$; exec sleep 300'],
    timeout => 1,
});
check_equal(
    'exec-status returns exit code 124 after a timeout', $timeout_status->{exitcode}, 124,
);
check_equal('timed-out', $timeout_status->{'timed-out'}, 1);
die "the command did not print one process ID followed by a newline:"
    . " $timeout_status->{stdout}\n"
    if $timeout_status->{stdout} !~ m/\A(\d+)\n\z/;
my $command_pid = $1;
die "process $command_pid still exists after exec-status returned the timeout result\n"
    if kill(0, $command_pid);
print "OK:timeout stops the command process\n";

my $read_pid = call_exec({ command => ['true'] });
wait_for_exit($read_pid);
check_dies(
    'exec-status rejects a second result read',
    qr/no stored result for command $read_pid in VM $VMID/,
    sub { call_exec_status($EXEC_USER, $VMID, $read_pid) },
);
check_dies(
    'exec-status rejects a pid from another VM',
    qr/no stored result for command \d+ in VM $OTHER_VMID/,
    sub {
        call_exec_status($OWNER_USER, $OTHER_VMID, call_exec({ command => ['true'] }));
    },
);
check_dies(
    'exec rejects invalid base64 input-data',
    qr/parameter 'input-data' is not valid base64/,
    sub { call_exec({ command => ['true'], 'input-data' => 'not base64!' }) },
);
check_dies(
    'exec rejects a timeout above the schema maximum',
    qr/Parameter verification failed/,
    sub { call_exec({ command => ['true'], timeout => $EXEC_TIMEOUT_ABOVE_MAXIMUM }) },
);
check_dies(
    'exec-status reports a missing program',
    qr/execution of command \d+ in VM $VMID failed: Agent error: /,
    sub { run_command({ command => ["$work_directory/missing-program"] }) },
);

my $file_path = "$work_directory/written file";
my $file_content = join('', map { chr($_) } 0 .. 255) x 16;
call_file_write($file_path, encode_base64($file_content, ''));
my $read_result = call_file_read($file_path);
check_equal(
    'file-read returns the bytes written by file-write',
    $read_result->{content},
    encode_base64($file_content, ''),
);
die "file-read marked a file below the read limit as truncated\n" if $read_result->{truncated};

call_file_write($file_path, encode_base64('new', ''));
$read_result = call_file_read($file_path);
check_equal(
    'file-write replaces existing content', decode_base64($read_result->{content}), 'new',
);

call_file_write($file_path, '');
$read_result = call_file_read($file_path);
check_equal(
    'file-read returns empty content after an empty write', $read_result->{content}, '',
);
check_equal('an empty file-write truncates the file to zero bytes', -s $file_path, 0);

my $large_path = "$work_directory/large";
open(my $large_handle, '>', $large_path)
    or die "unable to open $large_path for writing: $!\n";
print {$large_handle} 'x' x ($FILE_READ_LIMIT + 1);
close($large_handle) or die "unable to close $large_path: $!\n";
$read_result = call_file_read($large_path);
check_equal(
    'file-read returns four mebibytes from a larger file',
    length(decode_base64($read_result->{content})),
    $FILE_READ_LIMIT,
);
check_equal('truncated', $read_result->{truncated}, 1);

check_dies(
    'file-read reports a missing file',
    qr/Agent error: /,
    sub { call_file_read("$work_directory/missing") },
);
check_dies(
    'file-write reports a missing parent directory',
    qr/Agent error: /,
    sub { call_file_write("$work_directory/missing/file", 'bmV3') },
);
check_dies(
    'file-read rejects a relative path',
    qr/parameter 'file' must be an absolute path/,
    sub { call_file_read('relative') },
);
check_dies(
    'file-write rejects invalid base64 content',
    qr/parameter 'content' is not valid base64/,
    sub { call_file_write($file_path, 'a') },
);

my $task_count = 0;
for my $log (glob('/var/log/pve/tasks/*/UPID*')) {
    my $upid = PVE::UPID::decode(basename($log));
    next if !$upid || $upid->{type} ne 'qmexec' || $upid->{id} ne $VMID;
    next if $upid->{starttime} < $test_start;
    die "qmexec task has unexpected user $upid->{user}\n" if $upid->{user} ne $EXEC_USER;
    $task_count++;
}
check_equal('qmexec task count matches returned pid count', $task_count, $started_count);

my $guest_calls = {
    'exec' => sub { call_exec({ command => ['true'] }) },
    'file-write' => sub { call_file_write($file_path, 'bmV3') },
    'file-read' => sub { call_file_read($file_path) },
};

stop_agent($agent_pid);
$agent_pid = undef;
unlink($socket_path);
for my $name (sort keys %$guest_calls) {
    check_dies(
        "$name fails when the guest agent is stopped",
        qr/\AQEMU guest agent is not running$/,
        $guest_calls->{$name},
    );
}

$vm_config = {};
for my $name (sort keys %$guest_calls) {
    check_dies(
        "$name fails when no guest agent is configured",
        qr/\ANo QEMU guest agent configured$/,
        $guest_calls->{$name},
    );
}

print "all tests passed\n";

exit(0);
