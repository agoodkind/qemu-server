package PVE::API2::Qemu::Guest;

use strict;
use warnings;

use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX qw(SIGCHLD SIG_BLOCK SIG_UNBLOCK SIG_SETMASK sigprocmask);
use Time::HiRes qw();

use PVE::JSONSchema qw(get_standard_option);
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Agent qw(agent_cmd);
use PVE::RPCEnvironment;
use PVE::GuestExecResult;
use PVE::Tools;

# pve-http-server rejects a request body above 512 KiB ($limit_max_post in
# PVE/APIServer/AnyEvent.pm). A form-encoded body expands each of '+', '/', and '=' to three
# bytes. The worst case body of a 128 KiB base64 value is 384 KiB.
my $GUEST_BASE64_MAX_LENGTH = 128 * 1024;
my $GUEST_BASE64_REGEX = qr{(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?};
my $GUEST_EXEC_TIMEOUT_DEFAULT = 120;
my $GUEST_EXEC_TIMEOUT_MAX = 3600;
my $GUEST_EXEC_OUTPUT_LIMIT = PVE::GuestExecResult::output_limit();
my $GUEST_FILE_READ_LIMIT = 4 * 1024 * 1024;
my $GUEST_FILE_PATH_MAX_LENGTH = 4096;
my $GUEST_FILE_READ_CHUNK_SIZE = 1024 * 1024;
my $GUEST_KILL_GRACE_SECONDS = 5;
my $GUEST_POLL_MIN_SECONDS = 0.05;
my $GUEST_POLL_MAX_SECONDS = 1;
my $GUEST_EXEC_TIMEOUT_EXITCODE = 124;
my $GUEST_SIGNAL_EXITCODE_BASE = 128;
# qemu-ga disables guest-exec and guest-exec-status while guest filesystems are frozen.
my $GUEST_DISABLED_COMMAND_REGEX =
    qr/\AAgent error: Command guest-exec(?:-status)? has been disabled/;

my $decode_guest_base64 = sub {
    my ($name, $value) = @_;

    die "parameter '$name' is not valid base64\n" if $value !~ m/\A$GUEST_BASE64_REGEX\z/;
    return decode_base64($value);
};

# $check_guest_file_path returns an absolute path without Perl's taint flag.
my $check_guest_file_path = sub {
    my ($file) = @_;

    die "parameter 'file' must be an absolute path\n" if $file !~ m!\A(/[^\0]*)\z!s;
    return $1;
};

# Filesystem operations in taint mode require untainted identifiers.
my $untaint_decimal = sub {
    my ($name, $value) = @_;

    die "parameter '$name' is not a decimal number\n" if !defined($value) || $value !~ m/\A(\d+)\z/;
    return $1;
};

my $untaint_command = sub {
    my ($command) = @_;

    my @untainted;
    for my $argument (@$command) {
        die "a command argument contains a NUL byte\n" if $argument !~ m/\A([^\0]*)\z/s;
        push @untainted, $1;
    }
    return \@untainted;
};

my $assert_guest_agent = sub {
    my ($vmid) = @_;

    my $conf = PVE::QemuConfig->load_config($vmid);
    PVE::QemuServer::Agent::assert_agent_available($vmid, $conf);
    return $conf;
};

my $plan_poll = sub {
    my ($interval, $deadline, $now) = @_;

    my $remaining = $deadline - $now;
    return (0, $interval, 1) if $remaining <= 0;

    my $wait = $interval;
    $wait = $remaining if $wait > $remaining;
    my $next_interval = $interval * 2;
    $next_interval = $GUEST_POLL_MAX_SECONDS if $next_interval > $GUEST_POLL_MAX_SECONDS;
    return ($wait, $next_interval, 0);
};

# The guest agent deletes an exited command record after returning its status.
my $wait_for_guest_exit = sub {
    my ($vmid, $conf, $guest_pid, $deadline) = @_;

    my $interval = $GUEST_POLL_MIN_SECONDS;
    while (1) {
        my $status =
            eval { PVE::QemuServer::Agent::qemu_exec_status($vmid, $conf, $guest_pid) };
        if (my $error = $@) {
            die $error if $error !~ $GUEST_DISABLED_COMMAND_REGEX;
        } elsif ($status->{exited}) {
            return $status;
        }

        my ($wait, $next_interval, $expired) =
            $plan_poll->($interval, $deadline, Time::HiRes::time());
        return undef if $expired;

        Time::HiRes::sleep($wait);
        $interval = $next_interval;
    }
};

# A disabled guest-exec response means the command has not started.
my $start_guest_command = sub {
    my ($vmid, $conf, $input, $command, $deadline) = @_;

    my $interval = $GUEST_POLL_MIN_SECONDS;
    while (1) {
        # qemu_exec removes the program from the supplied array.
        my $started =
            eval { PVE::QemuServer::Agent::qemu_exec($vmid, $conf, $input, [@$command]) };
        my $error = $@;
        return $started if !$error;
        die $error if $error !~ $GUEST_DISABLED_COMMAND_REGEX;

        my ($wait, $next_interval, $expired) =
            $plan_poll->($interval, $deadline, Time::HiRes::time());
        die $error if $expired;

        Time::HiRes::sleep($wait);
        $interval = $next_interval;
    }
};

# Signaling requires kill in the guest because the guest agent has no signal command.
# Signals target only the command process; child processes can continue running.
my $signal_guest_process = sub {
    my ($vmid, $conf, $signal, $guest_pid) = @_;

    # guest-exec requires JSON strings for arguments, including the process ID.
    my $kill_command = ['kill', "-$signal", '--', "$guest_pid"];
    my $started = PVE::QemuServer::Agent::qemu_exec($vmid, $conf, undef, $kill_command);
    my $deadline = Time::HiRes::time() + $GUEST_KILL_GRACE_SECONDS;
    $wait_for_guest_exit->($vmid, $conf, $started->{pid}, $deadline);
};

my $terminate_guest_process = sub {
    my ($vmid, $conf, $guest_pid) = @_;

    $signal_guest_process->($vmid, $conf, 'TERM', $guest_pid);
    my $grace_deadline = Time::HiRes::time() + $GUEST_KILL_GRACE_SECONDS;
    my $status = $wait_for_guest_exit->($vmid, $conf, $guest_pid, $grace_deadline);
    return $status if $status;

    $signal_guest_process->($vmid, $conf, 'KILL', $guest_pid);
    $grace_deadline = Time::HiRes::time() + $GUEST_KILL_GRACE_SECONDS;
    return $wait_for_guest_exit->($vmid, $conf, $guest_pid, $grace_deadline);
};

my $run_in_vm = sub {
    my ($vmid, $command, $input, $timeout, $output_limit) = @_;

    my $conf = $assert_guest_agent->($vmid);

    # Omitting input-data connects standard input to /dev/null.
    $input = undef if defined($input) && !length($input);

    my $deadline = Time::HiRes::time() + $timeout;
    my $started = $start_guest_command->($vmid, $conf, $input, $command, $deadline);
    my $guest_pid = $started->{pid};

    my $status = $wait_for_guest_exit->($vmid, $conf, $guest_pid, $deadline);
    my $timed_out = 0;
    if (!$status) {
        $timed_out = 1;
        $status = eval { $terminate_guest_process->($vmid, $conf, $guest_pid) };
        warn "unable to terminate guest process $guest_pid in VM $vmid: $@" if $@;
        $status //= {};
    }

    my $captured = {
        stdout => $status->{'out-data'} // '',
        stderr => $status->{'err-data'} // '',
    };
    my $truncated = {
        stdout => $status->{'out-truncated'} ? 1 : 0,
        stderr => $status->{'err-truncated'} ? 1 : 0,
    };
    for my $stream ('stdout', 'stderr') {
        next if length($captured->{$stream}) <= $output_limit;
        $captured->{$stream} = substr($captured->{$stream}, 0, $output_limit);
        $truncated->{$stream} = 1;
    }

    return ($GUEST_EXEC_TIMEOUT_EXITCODE, $captured, $truncated, 1) if $timed_out;

    my $exitcode = $status->{exitcode};
    if (!defined($exitcode)) {
        die "guest agent did not return an exit code or signal for process $guest_pid\n"
            if !defined($status->{signal});
        $exitcode = $GUEST_SIGNAL_EXITCODE_BASE + $status->{signal};
    }

    return ($exitcode, $captured, $truncated, 0);
};

my $run_exec_worker = sub {
    my ($vmid, $exec_id, $command, $input, $timeout) = @_;

    PVE::GuestExecResult::worker_started('qemu', $vmid, $exec_id);
    my $status = {};
    my $captured = { stdout => '', stderr => '' };
    eval {
        my ($exitcode, $output, $truncated, $timed_out) =
            $run_in_vm->($vmid, $command, $input, $timeout, $GUEST_EXEC_OUTPUT_LIMIT);
        $captured = $output;
        $status->{exitcode} = 0 + $exitcode;
        $status->{'out-truncated'} = 1 if $truncated->{stdout};
        $status->{'err-truncated'} = 1 if $truncated->{stderr};
        $status->{'timed-out'} = 1 if $timed_out;
    };
    if (my $error = $@) {
        chomp($error);
        $status = { error => $error };
    }

    PVE::GuestExecResult::complete('qemu', $vmid, $exec_id, $status, $captured);
    die "command timed out after $timeout seconds\n" if $status->{'timed-out'};
};

# The guest agent retains unclosed file handles until it restarts.
my $with_guest_file = sub {
    my ($vmid, $conf, $file, $mode, $code) = @_;

    my $handle =
        agent_cmd($vmid, $conf, 'file-open', { path => $file, mode => $mode }, "can't open file");

    my $result = eval { $code->($handle) };
    my $error = $@;

    eval { agent_cmd($vmid, $conf, 'file-close', { handle => $handle }, "can't close file") };
    my $close_error = $@;

    die $error if $error;
    die $close_error if $close_error;
    return $result;
};

sub exec_output_limit {
    return $GUEST_EXEC_OUTPUT_LIMIT;
}

sub file_read_limit {
    return $GUEST_FILE_READ_LIMIT;
}

sub register_methods {
    my ($class) = @_;

    $class->register_method({
        name => 'exec',
        path => '{vmid}/exec',
        method => 'POST',
        protected => 1,
        proxyto => 'node',
        expose_credentials => 1,
        permissions => {
            check => ['perm', '/vms/{vmid}', ['VM.Guest.Exec']],
        },
        description => 'Start a command asynchronously in a running VM through the QEMU guest'
            . ' agent. Get the result with exec-status.',
        parameters => {
            additionalProperties => 0,
            properties => {
                node => get_standard_option('pve-node'),
                vmid => get_standard_option(
                    'pve-vmid',
                    { completion => \&PVE::QemuServer::complete_vmid_running },
                ),
                command => {
                    type => 'array',
                    description => 'The command as a list of program and arguments.',
                    minItems => 1,
                    items => {
                        type => 'string',
                        description => 'One part of the program and arguments.',
                    },
                },
                'input-data' => {
                    type => 'string',
                    maxLength => $GUEST_BASE64_MAX_LENGTH,
                    description => 'Base64 encoded data for the standard input of the command.',
                    optional => 1,
                },
                timeout => {
                    type => 'integer',
                    minimum => 1,
                    maximum => $GUEST_EXEC_TIMEOUT_MAX,
                    default => $GUEST_EXEC_TIMEOUT_DEFAULT,
                    description => 'Seconds until the command is stopped.',
                    optional => 1,
                },
                'result-retention' => {
                    type => 'string',
                    enum => ['acknowledged'],
                    default => 'acknowledged',
                    optional => 1,
                    description => 'Retain completed results until acknowledgment or expiry.',
                },
            },
        },
        returns => {
            type => 'object',
            properties => {
                pid => {
                    type => 'integer',
                    description => 'The identifier of the command for exec-status. It is a'
                        . ' random number, not a process ID.',
                },
            },
        },
        code => sub {
            my ($param) = @_;

            # rest_handler stores the authenticated user of this request in the credentials
            # immediately before it calls the method. The user of the environment can belong
            # to another request or be empty, because auth_handler sets it before the body
            # arrives and every request clears it.
            my $rpcenv = PVE::RPCEnvironment::get();
            my $credentials = $rpcenv->get_credentials(1) // {};
            my $authuser = $credentials->{userid};
            die "the authenticated user of the request is not available to exec\n"
                if !defined($authuser);

            my $vmid = $untaint_decimal->('vmid', $param->{vmid});
            my $input;
            if (defined($param->{'input-data'})) {
                $input = $decode_guest_base64->('input-data', $param->{'input-data'});
            }
            my $timeout =
                $untaint_decimal->('timeout', $param->{timeout} // $GUEST_EXEC_TIMEOUT_DEFAULT);
            my $command = $untaint_command->($param->{command});

            $assert_guest_agent->($vmid);
            my $exec_id = PVE::GuestExecResult::reserve('qemu', $vmid);

            # fork_worker waits for the worker with a read that a SIGCHLD from an earlier
            # worker interrupts, and then fails with "got no worker upid". SIGCHLD stays
            # blocked until fork_worker returns, and the signal arrives afterwards.
            my $sigchld = POSIX::SigSet->new(SIGCHLD);
            my $previous_signals = POSIX::SigSet->new();
            sigprocmask(SIG_BLOCK, $sigchld, $previous_signals)
                or die "unable to block SIGCHLD: $!\n";
            eval {
                $rpcenv->fork_worker(
                    'qmexec',
                    $vmid,
                    $authuser,
                    sub {
                        sigprocmask(SIG_UNBLOCK, $sigchld);
                        $run_exec_worker->($vmid, $exec_id, $command, $input, $timeout);
                    },
                );
            };
            my $fork_error = $@;
            sigprocmask(SIG_SETMASK, $previous_signals);
            die $fork_error if $fork_error;

            return { pid => 0 + $exec_id };
        },
    });

    $class->register_method({
        name => 'exec_status',
        path => '{vmid}/exec-status',
        method => 'GET',
        protected => 1,
        proxyto => 'node',
        permissions => {
            check => ['perm', '/vms/{vmid}', ['VM.Guest.Exec']],
        },
        description => 'Read a command result until exec-ack deletes it or one hour passes.',
        parameters => {
            additionalProperties => 0,
            properties => {
                node => get_standard_option('pve-node'),
                vmid => get_standard_option(
                    'pve-vmid',
                    { completion => \&PVE::QemuServer::complete_vmid_running },
                ),
                pid => {
                    type => 'integer',
                    minimum => 1,
                    description => 'The identifier that exec returned.',
                },
            },
        },
        returns => {
            type => 'object',
            properties => {
                exited => {
                    type => 'boolean',
                    description => 'Set to 1 when the command has exited.',
                },
                exitcode => {
                    type => 'integer',
                    optional => 1,
                    description => 'The exit code of the command, or 128 plus the signal number'
                        . " when a signal ended it. A command that exceeded its timeout has"
                        . " $GUEST_EXEC_TIMEOUT_EXITCODE.",
                },
                'timed-out' => {
                    type => 'boolean',
                    optional => 1,
                    description => 'Set when the command exceeded its timeout and was stopped.',
                },
                'out-data' => {
                    type => 'string',
                    optional => 1,
                    description => 'Base64 encoded standard output of the command.',
                },
                'err-data' => {
                    type => 'string',
                    optional => 1,
                    description => 'Base64 encoded standard error of the command.',
                },
                'out-truncated' => {
                    type => 'boolean',
                    optional => 1,
                    description =>
                        "Set when the standard output exceeded $GUEST_EXEC_OUTPUT_LIMIT bytes.",
                },
                'err-truncated' => {
                    type => 'boolean',
                    optional => 1,
                    description =>
                        "Set when the standard error exceeded $GUEST_EXEC_OUTPUT_LIMIT bytes.",
                },
            },
        },
        code => sub {
            my ($param) = @_;

            my $vmid = $untaint_decimal->('vmid', $param->{vmid});
            my $exec_id = $untaint_decimal->('pid', $param->{pid});

            return PVE::GuestExecResult::read('qemu', $vmid, $exec_id);
        },
    });

    $class->register_method({
        name => 'exec_ack',
        path => '{vmid}/exec-ack',
        method => 'POST',
        protected => 1,
        proxyto => 'node',
        permissions => {
            check => ['perm', '/vms/{vmid}', ['VM.Guest.Exec']],
        },
        description => 'Acknowledge receipt and delete a completed command result.'
            . ' Repeated acknowledgment succeeds.',
        parameters => {
            additionalProperties => 0,
            properties => {
                node => get_standard_option('pve-node'),
                vmid => get_standard_option(
                    'pve-vmid', { completion => \&PVE::QemuServer::complete_vmid_running },
                ),
                pid => {
                    type => 'integer',
                    minimum => 1,
                    description => 'The identifier that exec returned.',
                },
            },
        },
        returns => { type => 'null' },
        code => sub {
            my ($param) = @_;

            my $vmid = $untaint_decimal->('vmid', $param->{vmid});
            my $exec_id = $untaint_decimal->('pid', $param->{pid});
            return PVE::GuestExecResult::acknowledge('qemu', $vmid, $exec_id);
        },
    });

    $class->register_method({
        name => 'file_write',
        path => '{vmid}/file-write',
        method => 'POST',
        protected => 1,
        proxyto => 'node',
        permissions => {
            check => ['perm', '/vms/{vmid}', ['VM.Guest.FileWrite']],
        },
        description =>
            'Create or overwrite a file in a running VM through the QEMU guest agent.',
        parameters => {
            additionalProperties => 0,
            properties => {
                node => get_standard_option('pve-node'),
                vmid => get_standard_option(
                    'pve-vmid',
                    { completion => \&PVE::QemuServer::complete_vmid_running },
                ),
                file => {
                    type => 'string',
                    maxLength => $GUEST_FILE_PATH_MAX_LENGTH,
                    description => 'The absolute path to the file in the VM.',
                },
                content => {
                    type => 'string',
                    maxLength => $GUEST_BASE64_MAX_LENGTH,
                    description => 'The base64 encoded content of the file.',
                },
            },
        },
        returns => { type => 'null' },
        code => sub {
            my ($param) = @_;

            my $vmid = $untaint_decimal->('vmid', $param->{vmid});
            my $file = $check_guest_file_path->($param->{file});
            my $content = $decode_guest_base64->('content', $param->{content});
            my $content_length = length($content);

            my $conf = PVE::QemuConfig->load_config($vmid);

            $with_guest_file->(
                $vmid,
                $conf,
                $file,
                'wb',
                sub {
                    my ($handle) = @_;

                    # Opening the file in wb mode already truncates existing content.
                    return if !$content_length;

                    my $written = agent_cmd(
                        $vmid,
                        $conf,
                        'file-write',
                        { handle => $handle, 'buf-b64' => $param->{content} },
                        "can't write to file",
                    );
                    die "guest agent reported $written->{count} bytes written to $file in VM"
                        . " $vmid instead of $content_length bytes\n"
                        if $written->{count} != $content_length;
                },
            );

            return;
        },
    });

    $class->register_method({
        name => 'file_read',
        path => '{vmid}/file-read',
        method => 'GET',
        protected => 1,
        proxyto => 'node',
        permissions => {
            check => ['perm', '/vms/{vmid}', ['VM.Guest.FileRead']],
        },
        description => "Read up to $GUEST_FILE_READ_LIMIT bytes from a file in a running VM"
            . ' through the QEMU guest agent.',
        parameters => {
            additionalProperties => 0,
            properties => {
                node => get_standard_option('pve-node'),
                vmid => get_standard_option(
                    'pve-vmid',
                    { completion => \&PVE::QemuServer::complete_vmid_running },
                ),
                file => {
                    type => 'string',
                    maxLength => $GUEST_FILE_PATH_MAX_LENGTH,
                    description => 'The absolute path to the file in the VM.',
                },
            },
        },
        returns => {
            type => 'object',
            properties => {
                content => {
                    type => 'string',
                    description => 'The base64 encoded content of the file.',
                },
                truncated => {
                    type => 'boolean',
                    optional => 1,
                    description => 'Set when the file is larger than the read limit.',
                },
            },
        },
        code => sub {
            my ($param) = @_;

            my $vmid = $untaint_decimal->('vmid', $param->{vmid});
            my $file = $check_guest_file_path->($param->{file});

            my $conf = PVE::QemuConfig->load_config($vmid);

            # One byte beyond the limit shows that the file is larger.
            my $read_size = $GUEST_FILE_READ_LIMIT + 1;
            my $content = $with_guest_file->(
                $vmid,
                $conf,
                $file,
                'r',
                sub {
                    my ($handle) = @_;

                    my $data = '';
                    my $end_of_file = 0;
                    while (!$end_of_file && length($data) < $read_size) {
                        my $chunk_size = $read_size - length($data);
                        if ($chunk_size > $GUEST_FILE_READ_CHUNK_SIZE) {
                            $chunk_size = $GUEST_FILE_READ_CHUNK_SIZE;
                        }
                        my $read = agent_cmd(
                            $vmid,
                            $conf,
                            'file-read',
                            { handle => $handle, count => $chunk_size },
                            "can't read from file",
                        );
                        $data .= decode_base64($read->{'buf-b64'});
                        $end_of_file = $read->{eof} ? 1 : 0;
                    }
                    return $data;
                },
            );

            my $result = {};
            if (length($content) > $GUEST_FILE_READ_LIMIT) {
                $content = substr($content, 0, $GUEST_FILE_READ_LIMIT);
                $result->{truncated} = 1;
            }
            $result->{content} = encode_base64($content, '');

            return $result;
        },
    });

    return;
}

1;
