#!/usr/bin/perl -T

# qemu-ga runs commands on the test host as the test user.

use strict;
use warnings;

use File::Basename qw(basename);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Getopt::Long qw(GetOptions);
use JSON;
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX;
use Time::HiRes qw();

use lib qw(.. .);

use HTTP::Status qw(:constants);

use PVE::API2::Qemu::Guest;
use PVE::ProcFSTools;
use PVE::QemuConfig;
use PVE::QemuServer::Helpers;
use PVE::QemuServer::Monitor;
use PVE::RPCEnvironment;
use PVE::UPID;

use GuestTestRequest;

my $TEST_PROCESS_ID = $$;
my $AGENT_DIAGNOSTIC_LIMIT = 8192;
my $AGENT_DIAGNOSTIC_TIMEOUT = 3;
my $result_retention_only = 0;
GetOptions('result-retention' => \$result_retention_only)
    or die "invalid guest-agent-test option\n";

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
my $FROZEN_SECONDS = 3;
my $FROZEN_COMMAND_EXITCODE = 7;
my $EXEC_OUTPUT_LIMIT = PVE::API2::Qemu::Guest::exec_output_limit();
my $FILE_READ_LIMIT = PVE::API2::Qemu::Guest::file_read_limit();

my $vm_config = { agent => '1' };
my $read_proc_starttime = \&PVE::ProcFSTools::read_proc_starttime;

{
    no warnings qw(redefine once);
    *PVE::QemuConfig::load_config = sub { return $vm_config };
    *PVE::QemuServer::Helpers::vm_running_locally = sub { return 1 };
    # The amd64 emulator reports different worker start times during fork_worker.
    # Result storage reads the actual process information.
    *PVE::ProcFSTools::read_proc_starttime = sub {
        return 1 if caller eq 'PVE::RESTEnvironment';
        return $read_proc_starttime->(@_);
    };
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
    my ($socket_path, $state_directory) = @_;

    unlink($socket_path);
    my $pid = fork() // die "fork failed: $!\n";
    if (!$pid) {
        exec {$QEMU_GA} (
            $QEMU_GA,
            '--verbose',
            '--method', 'unix-listen',
            '--path', $socket_path,
            '--statedir', $state_directory,
            '--pidfile', "$state_directory/qemu-ga.pid",
            '--logfile', "$state_directory/qemu-ga.log",
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

sub report_agent_failure {
    my ($label, $pid, $directory) = @_;

    my $reaped = 0;
    eval {
        my $info = PVE::ProcFSTools::read_proc_pid_stat($pid);
        my $metadata = {
            agent => $label,
            pid => 0 + $pid,
            owner_pid => 0 + $$,
            socket_present => -S $socket_path ? 1 : 0,
            signal_probe => 0 + kill(0, $pid),
        };
        if ($info) {
            $metadata->{process_state} = $info->{status};
            $metadata->{process_starttime} = $info->{starttime};
        }
        my $waited = waitpid($pid, WNOHANG);
        my $status = $?;
        $metadata->{waitpid} = 0 + $waited;
        if ($waited == $pid) {
            $reaped = 1;
            $metadata->{exit_code} = $status >> 8;
            $metadata->{signal} = $status & 127;
        }
        $metadata->{wait_error} = "$!" if $waited < 0;
        print STDERR 'QGA process diagnostic: ', encode_json($metadata), "\n";
    };
    if (my $error = $@) {
        print STDERR "QGA process diagnostic failed: ", substr($error, 0, $AGENT_DIAGNOSTIC_LIMIT);
    }

    eval {
        PVE::QemuServer::Monitor::mon_cmd(
            $VMID, 'guest-ping', timeout => $AGENT_DIAGNOSTIC_TIMEOUT,
        );
    };
    if (my $error = $@) {
        print STDERR "QGA ping diagnostic failed: ", substr($error, 0, $AGENT_DIAGNOSTIC_LIMIT);
    } else {
        print STDERR "QGA ping diagnostic succeeded\n";
    }

    eval {
        my $log_file = "$directory/qemu-ga.log";
        open(my $handle, '<', $log_file) or die "unable to read the QGA log: $!\n";
        my $size = -s $handle;
        die "unable to measure the QGA log: $!\n" if !defined($size);
        my $offset = $size - $AGENT_DIAGNOSTIC_LIMIT;
        $offset = 0 if $offset < 0;
        seek($handle, $offset, SEEK_SET) or die "unable to seek in the QGA log: $!\n";
        my $count = read($handle, my $log, $AGENT_DIAGNOSTIC_LIMIT);
        die "unable to read the QGA log: $!\n" if !defined($count);
        close($handle) or die "unable to close the QGA log: $!\n";
        print STDERR "QGA log tail ($label, $count bytes):\n", $log, "\n";
    };
    if (my $error = $@) {
        print STDERR "QGA log diagnostic failed: ", substr($error, 0, $AGENT_DIAGNOSTIC_LIMIT);
    }
    return $reaped;
}

my $agent_pid = start_agent($socket_path, $work_directory);
my $frozen_agent_pid;
END {
    if (defined($TEST_PROCESS_ID) && $$ == $TEST_PROCESS_ID) {
        my $exit_status = $?;
        if ($exit_status) {
            if ($agent_pid) {
                my $reaped = report_agent_failure('primary', $agent_pid, $work_directory);
                $agent_pid = undef if $reaped;
            }
            if ($frozen_agent_pid) {
                my $reaped = report_agent_failure(
                    'frozen', $frozen_agent_pid, "$work_directory/frozen",
                );
                $frozen_agent_pid = undef if $reaped;
            }
        }
        stop_agent($agent_pid) if $agent_pid;
        if ($frozen_agent_pid) {
            # qemu-ga ignores SIGTERM while frozen.
            kill('KILL', $frozen_agent_pid);
            waitpid($frozen_agent_pid, 0);
        }
        $? = $exit_status;
    }
}

my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'guest-permission-test.cfg');

my $test_start = time();
my $started_count = 0;
my @started_pids;

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
    push @started_pids, $result->{pid};
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

sub check_concurrent_result_ack {
    my ($pid, $original) = @_;

    my %expected = %$original;
    delete @expected{qw(stdout stderr)};
    my $encoder = JSON->new->canonical();
    my $expected_document = $encoder->encode(\%expected);
    my $reader_count = 4;
    my $reads_per_process = 8;
    pipe(my $ready_reader, my $ready_writer) or die "ready pipe failed: $!\n";
    pipe(my $start_reader, my $start_writer) or die "start pipe failed: $!\n";
    my @readers;
    my $error;
    {
        local $SIG{ALRM} = sub { die "concurrent result reads exceeded 20 seconds\n" };
        alarm(20);
        eval {
            for (1 .. $reader_count) {
                my $reader_pid = fork() // die "reader fork failed: $!\n";
                if (!$reader_pid) {
                    close($ready_reader);
                    close($start_writer);
                    my $success = eval {
                        my $initial = call_exec_status($EXEC_USER, $VMID, $pid);
                        die "a concurrent reader did not receive the complete original result\n"
                            if $encoder->encode($initial) ne $expected_document;
                        die "reader readiness failed: $!\n" if syswrite($ready_writer, '1') != 1;
                        die "reader start failed: $!\n" if sysread($start_reader, my $start, 1) != 1;
                        for (1 .. $reads_per_process) {
                            my $response = GuestTestRequest::guest_request(
                                $rpcenv, $EXEC_USER, 'GET', $VMID, 'exec-status', { pid => $pid },
                            );
                            if ($response->{status} == HTTP_OK) {
                                die "a concurrent reader received a partial or different result\n"
                                    if $encoder->encode($response->{data}) ne $expected_document;
                            } else {
                                my $message = $response->{message};
                                die "a concurrent reader received an unexpected error\n"
                                    if $response->{status} != HTTP_INTERNAL_SERVER_ERROR
                                    || !defined($message)
                                    || $message !~ m/\Ano stored result for command $pid in VM $VMID\n?\z/;
                            }
                        }
                        1;
                    };
                    print STDERR $@ if !$success;
                    POSIX::_exit($success ? 0 : 1);
                }
                push @readers, $reader_pid;
            }
            close($ready_writer);
            close($start_reader);
            my $ready_count = 0;
            while ($ready_count < $reader_count) {
                my $count = sysread($ready_reader, my $ready, $reader_count - $ready_count);
                die "a concurrent reader stopped before its start signal\n"
                    if !defined($count) || $count == 0;
                $ready_count += $count;
            }
            die "unable to start concurrent readers: $!\n"
                if syswrite($start_writer, '1' x $reader_count) != $reader_count;
            call_guest($EXEC_USER, 'POST', $VMID, 'exec-ack', { pid => $pid });
            while (@readers) {
                my $reader_pid = $readers[0];
                my $waited = waitpid($reader_pid, 0);
                my $exit_status = $?;
                shift @readers if $waited == $reader_pid;
                die "a concurrent result reader failed\n"
                    if $waited != $reader_pid || $exit_status != 0;
            }
        };
        $error = $@;
        alarm(0);
    }
    if ($error) {
        kill('KILL', @readers) if @readers;
        waitpid($_, 0) for @readers;
    }
    for my $handle ($ready_reader, $ready_writer, $start_reader, $start_writer) {
        close($handle) if defined(fileno($handle));
    }
    die $error if $error;
    print "OK:concurrent read and acknowledgment preserve complete results\n";
}

sub check_completed_record_capacity {
    my @completed_records;
    my $error;
    eval {
        for my $index (0 .. 1023) {
            my ($kind, $vmid) = ('lxc', $OTHER_VMID);
            if ($index % 2) {
                ($kind, $vmid) = ('qemu', $VMID);
            }
            my $pid = PVE::GuestExecResult::reserve($kind, $vmid);
            push @completed_records, { kind => $kind, vmid => $vmid, pid => $pid };
            PVE::GuestExecResult::complete(
                $kind, $vmid, $pid, { exitcode => 0 }, { stdout => '', stderr => '' },
            );
        }
        my $marker = "$work_directory/completed-record-command";
        check_dies(
            '1024 completed records across both guest kinds refuse execution',
            qr/command result storage capacity is full/,
            sub { call_exec({ command => ['mkdir', $marker] }) },
        );
        die "the completed-record refusal started the guest command\n" if -e $marker;
        my $released = shift @completed_records;
        PVE::GuestExecResult::acknowledge(
            $released->{kind}, $released->{vmid}, $released->{pid},
        );
        my $pid = call_exec({ command => ['mkdir', $marker] });
        wait_for_exit($pid);
        die "acknowledgment did not release one result record\n" if !-d $marker;
        call_guest($EXEC_USER, 'POST', $VMID, 'exec-ack', { pid => $pid });
    };
    $error = $@;
    for my $record (@completed_records) {
        PVE::GuestExecResult::acknowledge($record->{kind}, $record->{vmid}, $record->{pid});
    }
    die $error if $error;
    print "OK:acknowledgment releases completed-record capacity\n";
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

my $read_pid = call_exec({ command => ['head', '-c', '65536', '/dev/zero'] });
my $first_result = wait_for_exit($read_pid);
my $second_result = call_exec_status($EXEC_USER, $VMID, $read_pid);
check_equal('exec-status repeats the completed exit code', $second_result->{exitcode}, $first_result->{exitcode});
check_equal('exec-status repeats standard output', $second_result->{'out-data'}, $first_result->{'out-data'});
check_equal('exec-status repeats standard error', $second_result->{'err-data'}, $first_result->{'err-data'});
check_concurrent_result_ack($read_pid, $first_result);
call_guest($EXEC_USER, 'POST', $VMID, 'exec-ack', { pid => $read_pid });
check_dies(
    'exec-status rejects a result after acknowledgment',
    qr/no stored result for command $read_pid in VM $VMID/,
    sub { call_exec_status($EXEC_USER, $VMID, $read_pid) },
);
my $expiry_pid = call_exec({
    command => ['true'],
    'result-retention' => 'acknowledged',
});
wait_for_exit($expiry_pid);
my $expired_time = time() - 3601;
utime($expired_time, $expired_time, "/run/pve/qemu-exec/$VMID/$expiry_pid/status")
    or die "unable to expire the completed test result: $!\n";
check_dies(
    'exec-status expires a completed result after one hour',
    qr/no stored result for command $expiry_pid in VM $VMID/,
    sub { call_exec_status($EXEC_USER, $VMID, $expiry_pid) },
);
call_guest($EXEC_USER, 'POST', $VMID, 'exec-ack', { pid => $expiry_pid });
check_dies(
    'exec rejects a consuming result contract',
    qr/Parameter verification failed/,
    sub { call_exec({ command => ['true'], 'result-retention' => 'consumed' }) },
);
my $interrupted_pid = call_exec({ command => ['sleep', '2'] });
my $worker_file = "/run/pve/qemu-exec/$VMID/$interrupted_pid/worker";
my $worker_deadline = Time::HiRes::time() + $POLL_SECONDS;
while (!-e $worker_file) {
    die "the command worker did not register its process\n"
        if Time::HiRes::time() >= $worker_deadline;
    Time::HiRes::sleep(0.01);
}
my $worker_record = PVE::Tools::file_get_contents($worker_file);
die "the command worker record is invalid\n" if $worker_record !~ m/\A(\d+) \d+\z/;
my $worker_pid = $1;
kill('KILL', $worker_pid) or die "unable to interrupt the command worker: $!\n";
my $interrupted_deadline = Time::HiRes::time() + $POLL_SECONDS;
while (PVE::ProcFSTools::check_process_running($worker_pid)) {
    die "the interrupted command worker did not stop\n"
        if Time::HiRes::time() >= $interrupted_deadline;
    Time::HiRes::sleep(0.01);
}
check_dies(
    'exec-status reports an uncertain outcome after worker interruption',
    qr/command outcome is uncertain after worker interruption; do not replay the command/,
    sub { call_exec_status($EXEC_USER, $VMID, $interrupted_pid) },
);
my $expired_orphan = time() - 7201;
utime($expired_orphan, $expired_orphan, "/run/pve/qemu-exec/$VMID/$interrupted_pid")
    or die "unable to expire the interrupted test result: $!\n";
my @reserved_results;
for (1 .. 128) {
    my $reserved_pid = eval { PVE::GuestExecResult::reserve('lxc', $OTHER_VMID) };
    if (my $error = $@) {
        die $error if $error !~ m/command result storage capacity is full/;
        last;
    }
    push @reserved_results, $reserved_pid;
}
die "the host did not reserve result capacity\n" if !@reserved_results;
my $capacity_marker = "$work_directory/capacity-command";
check_dies(
    'LXC reservations refuse QEMU execution before the command starts',
    qr/command result storage capacity is full/,
    sub { call_exec({ command => ['mkdir', $capacity_marker] }) },
);
die "the capacity refusal started the guest command\n" if -e $capacity_marker;
my $expired_reservation = time() - 7201;
for my $reserved_pid (@reserved_results) {
    utime(
        $expired_reservation, $expired_reservation,
        "/run/pve/lxc-exec/$OTHER_VMID/$reserved_pid",
    ) or die "unable to expire the test reservation: $!\n";
}
my $after_expiry_pid = call_exec({ command => ['mkdir', $capacity_marker] });
wait_for_exit($after_expiry_pid);
die "expired reservations did not release command capacity\n" if !-e $capacity_marker;
call_guest($EXEC_USER, 'POST', $VMID, 'exec-ack', { pid => $after_expiry_pid });
for my $pid (@started_pids) {
    call_guest($EXEC_USER, 'POST', $VMID, 'exec-ack', { pid => $pid });
}
check_completed_record_capacity();
if ($result_retention_only) {
    print "command result retention tests passed\n";
    exit(0);
}

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

my $thawed_socket_path = "$SOCKET_DIRECTORY/$VMID-thawed.qga";
my $frozen_socket_path = "$SOCKET_DIRECTORY/$VMID-frozen.qga";
my $frozen_directory = "$work_directory/frozen";
my $marker_path = "$work_directory/marker";

# The first agent continues running commands while the second agent answers requests.
sub select_agent {
    my ($agent_socket_path) = @_;

    my $link_path = "$socket_path.link";
    unlink($link_path);
    link($agent_socket_path, $link_path) && rename($link_path, $socket_path)
        or die "agent socket replacement from $agent_socket_path to $socket_path failed: $!\n";
}

sub marker_command {
    my ($seconds) = @_;

    my $script = 'echo started >> "$1"; sleep "$2"; echo finished; exit "$3"';
    return ['sh', '-c', $script, 'sh', $marker_path, $seconds, $FROZEN_COMMAND_EXITCODE];
}

sub marker_line_count {
    open(my $marker_handle, '<', $marker_path) or return 0;
    my @lines = <$marker_handle>;
    close($marker_handle);
    return scalar(@lines);
}

sub wait_for_marker_lines {
    my ($count) = @_;

    my $deadline = Time::HiRes::time() + $POLL_SECONDS;
    while (marker_line_count() < $count) {
        die "marker file $marker_path did not contain $count lines within $POLL_SECONDS seconds\n"
            if Time::HiRes::time() >= $deadline;
        Time::HiRes::sleep(0.05);
    }
}

# qemu-ga starts frozen when qga.state.isfrozen exists in its state directory.
# The unprivileged test container cannot freeze a filesystem.
make_path($frozen_directory);
open(my $frozen_handle, '>', "$frozen_directory/qga.state.isfrozen")
    or die "file open failed for $frozen_directory/qga.state.isfrozen: $!\n";
close($frozen_handle) or die "file close failed for $frozen_directory/qga.state.isfrozen: $!\n";
unlink($thawed_socket_path);
link($socket_path, $thawed_socket_path)
    or die "socket link from $socket_path to $thawed_socket_path failed: $!\n";
$frozen_agent_pid = start_agent($frozen_socket_path, $frozen_directory);

my $frozen_status_pid = call_exec({ command => marker_command(5) });
wait_for_marker_lines(1);
select_agent($frozen_socket_path);
Time::HiRes::sleep($FROZEN_SECONDS);
select_agent($thawed_socket_path);
my $frozen_status = wait_for_exit($frozen_status_pid);
check_equal(
    'exec-status returns exit code 7 after guest-exec-status resumes',
    $frozen_status->{exitcode},
    $FROZEN_COMMAND_EXITCODE,
);
check_equal(
    'exec-status returns standard output after guest-exec-status resumes',
    $frozen_status->{stdout},
    "finished\n",
);
check_equal('command starts once despite disabled guest-exec-status', marker_line_count(), 1);

select_agent($frozen_socket_path);
my $frozen_start_pid = call_exec({ command => marker_command(0) });
Time::HiRes::sleep($FROZEN_SECONDS);
check_equal('command does not start while guest-exec is disabled', marker_line_count(), 1);
select_agent($thawed_socket_path);
my $frozen_start_status = wait_for_exit($frozen_start_pid);
check_equal(
    'exec-status returns exit code 7 after guest-exec resumes',
    $frozen_start_status->{exitcode},
    $FROZEN_COMMAND_EXITCODE,
);
check_equal(
    'exec-status returns standard output after guest-exec resumes',
    $frozen_start_status->{stdout},
    "finished\n",
);
check_equal('command starts once after guest-exec resumes', marker_line_count(), 2);

# The command exits before the timeout; a successful status read would return exit code 7.
my $frozen_timeout_pid = call_exec({ command => marker_command(2), timeout => 6 });
wait_for_marker_lines(3);
select_agent($frozen_socket_path);
my $frozen_timeout_status = wait_for_exit($frozen_timeout_pid);
check_equal(
    'exec-status returns exit code 124 while guest-exec-status stays disabled',
    $frozen_timeout_status->{exitcode},
    124,
);
check_equal(
    'exec-status reports timed-out while guest-exec-status stays disabled',
    $frozen_timeout_status->{'timed-out'},
    1,
);

# The thawed second agent has no record of commands started by the first agent.
PVE::QemuServer::Monitor::mon_cmd($VMID, 'guest-fsfreeze-thaw');
select_agent($thawed_socket_path);
my $other_agent_pid = call_exec({ command => marker_command(2) });
wait_for_marker_lines(4);
select_agent($frozen_socket_path);
check_dies(
    'exec-status reports an unknown process without waiting for the command timeout',
    qr/execution of command $other_agent_pid in VM $VMID failed: Agent error: PID /,
    sub { wait_for_exit($other_agent_pid) },
);
select_agent($thawed_socket_path);

stop_agent($frozen_agent_pid);
$frozen_agent_pid = undef;
unlink($thawed_socket_path, $frozen_socket_path);

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
