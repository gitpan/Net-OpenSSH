package Net::OpenSSH;

our $VERSION = '0.11';

use strict;
use warnings;

our $debug ||= 0;

my $append_fd_mode = ($] >= 5.008 ? '>>&' : '>&');

use Carp qw(carp croak);
use POSIX qw(:sys_wait_h);
use File::Spec;
use Cwd ();
use Scalar::Util ();
use Errno ();
use Net::OpenSSH::Constants qw(:error);

# { my $old = select; select STDERR; $| = 1; select $old }

sub _debug { print STDERR '# ', @_, "\n" }

sub _debug_dump {
    require Data::Dumper;
    local $Data::Dumper::Terse = 1;
    local $Data::Dumper::Indent = 0;
    my $head = shift;
    _debug("$head: ", Data::Dumper::Dumper(@_));
}

sub _hexdump {
    no warnings qw(uninitialized);
    my $data = shift;
    while ($data =~ /(.{1,32})/smg) {
        my $line=$1;
        my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                (("  ") x 32))[0..31];
        $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
        print STDERR "#> ", join(" ", @c, '|', $line), "\n";
    }
}

{
    my %good;

    sub _sub_options {
        my $sub = shift;
        $good{__PACKAGE__ . "::$sub"} = { map { $_ => 1 } @_ };
    }

    sub _croak_bad_options (\%) {
        my $opts = shift;
        if (%$opts) {
            my $good = $good{(caller 1)[3]};
            my @keys = ( $good ? grep !$good->{$_}, keys %$opts : keys %$opts);
            if (@keys) {
                my $s = (@keys > 1 ? 's' : '');
                croak "Invalid or bad combination of option$s ('" . CORE::join("', '", @keys) . "')";
            }
        }
    }
}

sub _set_error {
    my $self = shift;
    my $code = shift || 0;
    my $err = $self->{_error} = ( $code
                                  ? Scalar::Util::dualvar($code, (@_
                                                                  ? join(': ', @_)
                                                                  : "Unknown error $code"))
                                  : 0 );
    $debug and $debug & 1 and _debug "set_error($code - $err)";
    return $err
}

sub _check_master_and_clear_error {
    my $self = shift;
    $self->wait_for_master or return undef;
    $self->{_error} = 0;
    1;
}

my $obfuscate = sub {
    # just for the casual observer...
    my $txt = shift;
    $txt =~ s/(.)/chr(ord($1) ^ 47)/ge
        if defined $txt;
    $txt;
};
my $deobfuscate = $obfuscate;

sub new {
    my $class = shift;
    @_ & 1 and unshift @_, 'host';
    my %opts = @_;

    my $target = delete $opts{host};

    my ($user, $passwd, $host, $port) =
        $target =~ /^\s*(?:([^\@:]+)(?::(.*))?\@)?([^\@:]+)(?::([^\@:]+))?\s*$/
            or croak "bad host/target '$target' specification";

    $user = delete $opts{user} unless defined $user;
    $port = delete $opts{port} unless defined $port;
    $passwd = delete $opts{passwd} unless defined $passwd;
    my $ctl_path = delete $opts{ctl_path};
    my $ctl_dir = delete $opts{ctl_dir};
    my $ssh_cmd = delete $opts{ssh_cmd};
    $ssh_cmd = 'ssh' unless defined $ssh_cmd;
    my $scp_cmd = delete $opts{scp_cmd};
    my $timeout = delete $opts{timeout};
    my $strict_mode = delete $opts{strict_mode};
    $strict_mode = 1 unless defined $strict_mode;
    my $async = delete $opts{async};
    my $master_opts = delete $opts{master_opts};

    _croak_bad_options %opts;

    my @master_opts;
    if (defined $master_opts) {
	if (ref($master_opts)) {
	    @master_opts = @$master_opts;
	}
	else {
	    carp "'master_opts' argument looks like if it should be splited first"
		if $master_opts =~ /^-\w\s+\S/;
	    @master_opts = $master_opts;
	}
    }

    my @ssh_opts;
    push @ssh_opts, -o => "User $user" if defined $user;
    push @ssh_opts, -o => "Port $port" if defined $port;

    my $self = { _error => 0,
                 _ssh_cmd => $ssh_cmd,
		 _scp_cmd => $scp_cmd,
                 _pid => undef,
                 _host => $host,
                 _user => $user,
                 _port => $port,
                 _passwd => $obfuscate->($passwd),
                 _timeout => $timeout,
                 _home => eval { Cwd::realpath((getpwuid $>)[7]) },
                 _ssh_opts => \@ssh_opts,
		 _master_opts => \@master_opts };
    bless $self, $class;

    unless (defined $ctl_path) {
        $ctl_dir = File::Spec->catdir($self->{_home}, ".libnet-openssh-perl")
            unless defined $ctl_dir;

        mkdir $ctl_dir;
        unless (-d $ctl_dir) {
            $self->_set_error(OSSH_MASTER_FAILED, "unable to create ctl_dir $ctl_dir: $!");
            return $self;
        }

        my $target = join('-', grep defined, $user, $host, $port);

        for (1..10) {
            $ctl_path = File::Spec->join($ctl_dir, sprintf("%s-%d-%d", substr($target, 0, 20), $$, rand(1e6)));
            last unless -e $ctl_path
        }
        if (-e $ctl_path) {
            $self->_set_error(OSSH_MASTER_FAILED,
                              "unable to find unused name for ctl_path inside ctl_dir $ctl_dir");
            return undef;
        }
    }
    $ctl_dir = File::Spec->catpath((File::Spec->splitpath($ctl_path))[0,1], "");
    $debug and $debug & 2 and _debug "ctl_path: $ctl_path, ctl_dir: $ctl_dir";

    unless ($self->_is_secure_path($ctl_dir)) {
        $self->_set_error(OSSH_MASTER_FAILED, "ctl_dir $ctl_dir is not secure");
        return $self;
    }

    if ($strict_mode and !$self->_is_secure_path($ctl_dir)) {
 	$self->_set_error(OSSH_MASTER_FAILED, "ctl_dir $ctl_dir is not secure");
 	return $self;
    }

    $self->{_ctl_path} = $ctl_path;
    $self->_connect;
    $self;
}

sub _is_secure_path {
    my ($self, $path) = @_;
    my @parts = File::Spec->splitdir(Cwd::realpath($path));
    my $home = $self->{_home};
    for my $last (reverse 0..$#parts) {
        my $dir = File::Spec->catdir(@parts[0..$last]);
        unless (-d $dir) {
            $debug and $debug & 2 and _debug "$dir is not a directory";
            return undef;
        }
        my ($mode, $uid) = (stat $dir)[2, 4];
        $debug and $debug & 2 and _debug "_is_secure_path(dir: $dir, file mode: $mode, file uid: $uid, euid: $>";
        return undef unless(($uid == $> or $uid == 0 ) and (($mode & 022) == 0));
        return 1 if (defined $home and $home eq $dir);
    }
    return 1;
}

sub _make_call {
    my $self = shift;
    my @before = @{shift || []};
    my @args = ($self->{_ssh_cmd}, @before,
		-S => $self->{_ctl_path},
                @{$self->{_ssh_opts}}, '--', $self->{_host},
                (@_ ? "@_" : ()));
    $debug and $debug & 8 and _debug_dump 'call args' => \@args;
    @args;
}

sub _scp_cmd {
    my $self = shift;
    $self->{_scp_cmd} ||= do {
	my $scp = $self->{_ssh_cmd};
	$scp =~ s/ssh$/scp/i or croak "scp command name not set";
	$scp;
    }
}

sub _make_scp_call {
    my $self = shift;
    my @before = @{shift || []};
    my @args = ($self->_scp_cmd, @before,
		-o => "ControlPath $self->{_ctl_path}",
                @{$self->{_ssh_opts}}, '--', @_);

    $debug and $debug & 8 and _debug_dump 'scp call args' => \@args;
    @args;
}

sub _kill_master {
    my $self = shift;
    my $pid = delete $self->{_pid};
    if ($pid) {
        for my $sig (1, 1, 1, 9, 9) {
            kill $sig, $pid or return;
            waitpid($pid, WNOHANG) == $pid and return;
            select(undef, undef, undef, 1);
        }
    }
}

sub _connect {
    my ($self, $async) = @_;
    $self->_set_error;

    my $mpty;
    if (defined $self->{_passwd}) {
        _load_module('IO::Pty');
        $self->{_mpty} = $mpty = IO::Pty->new;
    }

    local $SIG{CHLD};
    my $pid = fork;
    unless (defined $pid) {
        $self->_set_error(OSSH_MASTER_FAILED, "unable to fork ssh master: $!");
        return undef;
    }
    unless ($pid) {
        $mpty->make_slave_controlling_terminal if $mpty;
        my @call = $self->_make_call([@{$self->{_master_opts}}, '-xMN']);
        eval { exec @call };
        POSIX::_exit(255);
    }
    $mpty->close_slave if $mpty;
    $self->{_pid} = $pid;
    $self->_wait_for_master($async, 1);
}

sub wait_for_master {
    my $self = shift;
    @_ <= 2 or croak 'Usage: $ssh->wait_for_master([$async])';
    $self->{_wfm_status}                  ? $self->_wait_for_master(@_) :
    $self->{_error} == OSSH_MASTER_FAILED ? undef                       :
                                            1;
}

my $wfm_error_prefix = "unable to stablish master ssh connection";

sub _wait_for_master {
    my ($self, $async, $reset) = @_;

    my $status = delete $self->{_wfm_status};
    my $bout = \($self->{_wfm_bout});

    my $mpty = $self->{_mpty};
    my $passwd = $deobfuscate->($self->{_passwd});

    if ($reset) {
        $$bout = '';
        $status = ( defined $passwd
                    ? 'waiting_for_password_prompt'
                    : 'waiting_for_socket' );
    }

    my $pid = $self->{_pid};
    my $ctl_path = $self->{_ctl_path};
    my $fnopty = fileno $mpty if defined $mpty;
    my $dt = ($async ? 0 : 0.1);
    my $timeout = $self->{_timeout};
    my $start_time = time;

    my $rv = '';
    vec($rv, $fnopty, 1) = 1 if $status eq 'waiting_for_password_prompt';

    while (1) {
        last if (defined $timeout and (time - $start_time) > $timeout);

        if (-e $ctl_path) {
            unless (-S $ctl_path) {
                $self->_set_error(OSSH_MASTER_FAILED, $wfm_error_prefix,
                                  "bad ssh master at $ctl_path, object is not a socket");
                $self->_kill_master;
                return undef;
            }
            my $check = $self->_master_ctl('check');
            if ($check =~ /pid=(\d+)/) {
                unless ($pid == $1) {
                    $self->_set_error(OSSH_MASTER_FAILED, $wfm_error_prefix,
                                      "bad ssh master at $ctl_path, socket owned by pid $1 (pid $pid expected)");
                    $self->_kill_master;
                    return undef;
                }
                return 1;
            }
        }
        if (waitpid($pid, WNOHANG) == $pid) {
            $self->_set_error(OSSH_MASTER_FAILED, $wfm_error_prefix,
                              "ssh master exited unexpectely");
            $self->{_master_status} = 'failed';
            return undef;
        }
        my $rv1 = $rv;
        my $n = select($rv1, undef, undef, $dt);
        if ($n > 0) {
            vec($rv1, $fnopty, 1)
                or die "internal error";
            my $read = sysread($mpty, $$bout, 4096, length $$bout);
            if ($read) {
                if ($status eq 'waiting_for_password_prompt') {
                    if ($$bout =~ /The authenticity of host.*can't be established/si) {
                        $self->_set_error(OSSH_MASTER_FAILED, $wfm_error_prefix,
                                          "the authenticity of the target host can't be established, try loging manually first");
                        $self->_kill_master;
                        return undef;
                    }
                    if ($$bout =~ s/^(.*:)//s) {
                        $debug and $debug & 4 and _debug "passwd requested ($1)";
                        print $mpty "$passwd\n";
                        $self->{_wfm_state} = 'password_sent';
                    }
                }
                else { $$bout = '' }
                next;
            }
            $async or select(undef, undef, undef, $dt);
        }
        if ($async) {
            $self->{_wfm_status} = $status;
            return 0;
        }
    }
    $self->_set_error(OSSH_MASTER_FAILED, $wfm_error_prefix, "ssh master login timed out");
    $self->_kill_master;
    undef
}

sub error { shift->{_error} }

sub _master_ctl {
    my ($self, $cmd) = @_;
    $self->capture({stderr_to_stdout => 1, ssh_opts => [-O => $cmd]});
}

sub system {
    my $self = shift;
    $self->_check_master_and_clear_error or return -1;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $tty = delete $opts{tty};
    my @args = $self->_quote_args(\%opts, @_);
    _croak_bad_options %opts;
    my @ssh_opts;
    $tty and push @ssh_opts, '-qt';
    my @call = $self->_make_call(\@ssh_opts, @args);
    $debug and $debug & 16 and _debug_dump system => \@call;
    CORE::system @call;
}

sub _make_pipe {
    my $self = shift;
    my ($r, $w);
    unless (pipe ($r, $w)) {
        $self->_set_error(OSSH_PIPE_FAILED, "unable to create pipe: $!");
        return ();
    }
    my $old = select;
    select $r; $|=1;
    select $w; $|=1;
    select $old;
    return ($r, $w);
}

my %loaded_module;
sub _load_module {
    my $module = shift;
    $loaded_module{$module} ||= do {
        eval "require $module; 1"
            or croak "unable to load Perl module $module";
        1
    }
}

sub _arg_quoter {
    sub {
        my $arg = shift;
        $arg =~ s|([^\w/-])|\\$1|g;
        $arg
    }
}

sub _quote_args {
    my $self = shift;
    my $opts = shift;
    ref $opts eq 'HASH' or die "internal error";
    my $quote = delete $opts->{quote_args};
    $quote = (@_ > 1) unless defined $quote;
    return @_ unless $quote;
    my $quoter = $self->_arg_quoter;
    wantarray ? map $quoter->($_), @_ : $quoter->($_[0])
}

sub shell_quote {
    shift->_quote_args({quote_args => 1}, @_);
}

sub _check_is_system_fh {
    my ($name, $fh) = @_;
    my $fn = fileno(defined $fh ? $fh : $name);
    return if (defined $fn and $fn >= 0);
    croak "child process $name is not a real system file handle";
}

sub open_ex {
    my $self = shift;
    $self->_check_master_and_clear_error or return ();
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    my ($stdin_pipe, $stdin_fh, $stdin_pty);
    ( $stdin_pipe = delete $opts{stdin_pipe} or
      $stdin_pty = delete $opts{stdin_pty} or
      $stdin_fh = delete $opts{stdin_fh} );

    my ($stdout_pipe, $stdout_fh, $stdout_pty);
    ( $stdout_pipe = delete $opts{stdout_pipe} or
      $stdout_pty = delete $opts{stdout_pty} or
      $stdout_fh = delete $opts{stdout_fh} );

    $stdout_pty and !$stdin_pty
        and croak "option stdout_pty requires stdin_pty set";

    my ($stderr_pipe, $stderr_fh, $stderr_to_stdout);
    ( $stderr_pipe = delete $opts{stderr_pipe} or
      $stderr_fh = delete $opts{stderr_fh} or
      $stderr_to_stdout = delete $opts{stderr_to_stdout} );

    my $tty = delete $opts{tty};
    my $close_slave_pty;
    if ($stdin_pty) {
        $tty = 1 unless defined $tty;
        $close_slave_pty = delete $opts{close_slave_pty};
        $close_slave_pty = 1 unless defined $close_slave_pty;
    }
    my @ssh_opts;
    my $ssh_opts = delete $opts{ssh_opts};
    if (defined $ssh_opts) {
	@ssh_opts = (ref $ssh_opts eq 'ARRAY' ? @$ssh_opts : $ssh_opts);
    }
    my $scp = delete $opts{_scp};

    my @args = $self->_quote_args(\%opts, @_);
    _croak_bad_options %opts;

    my ($rin, $win, $rout, $wout, $rerr, $werr);

    push @ssh_opts, '-qt' if ($tty or $stdin_pty);

    if ($stdin_pipe) {
        ($rin, $win) = $self->_make_pipe or return;
    }
    elsif ($stdin_pty) {
        _load_module('IO::Pty');
        $win = IO::Pty->new;
        $rin = $win->slave;
    }
    else {
        $rin = $stdin_fh;
    }
    _check_is_system_fh STDIN => $rin;

    if ($stdout_pipe) {
        ($rout, $wout) = $self->_make_pipe or return;
    }
    elsif ($stdout_pty) {
        $wout = $rin;
    }
    else {
        $wout = $stdout_fh;
    }
    _check_is_system_fh STDOUT => $wout;

    unless ($stderr_to_stdout) {
	if ($stderr_pipe) {
	    ($rerr, $werr) = $self->_make_pipe or return ();
	}
	elsif (defined $stderr_fh) {
	    $werr = $stderr_fh;
	}
	_check_is_system_fh STDERR => $werr;
    }

    if (defined $wout and fileno $wout < 1) {
	my $wout_dup;
	unless (open $wout_dup, '>>&', $wout) {
	    $self->_set_error(OSSH_SLAVE_FAILED,
			      "unable to dup child STDOUT: $!");
	    return ()
	}
	$wout = $wout_dup;
    }

    if (defined $werr and fileno $werr < 2) {
	my $werr_dup;
	unless (open $werr_dup, '>>&', $werr) {
	    $self->_set_error(OSSH_SLAVE_FAILED,
			      "unable to dup child STDERR: $!");
	    return ()
	}
	$werr = $werr_dup;
    }

    my $pid = fork;
    unless (defined $pid) {
        $self->_set_error(OSSH_SLAVE_FAILED, "unable to fork new ssh slave: $!");
        return ();
    }
    unless ($pid) {
        if (defined $rin) {
            $rin->make_slave_controlling_terminal if $stdin_pty;
	    unless (fileno $rin == 0) {
		open STDIN, '<&', $rin or POSIX::_exit(255);
	    }
	    $win and close $win;
        }
        if (defined $wout) {
	    unless (fileno $wout == 1) {
		open STDOUT, '>>&', $wout or POSIX::_exit(255);
	    }
            $rout and close $rout;
        }
        if (defined $werr) {
	    unless (fileno $werr == 2) {
		open STDERR, '>>&', $werr or POSIX::_exit(255);
	    }
	    $rerr and close $rerr;
        }
        elsif ($stderr_to_stdout) {
	    open STDERR, '>>&STDOUT' or POSIX::_exit(255);
        }
        my @call = ( $scp
		     ? $self->_make_scp_call(\@ssh_opts, @args)
		     : $self->_make_call(\@ssh_opts, @args) );
        $debug and $debug & 16 and _debug_dump open_ex => \@call;
        do { exec @call };
        POSIX::_exit(255);
    }
    $win->close_slave() if ($tty and defined $win and $close_slave_pty);
    wantarray ? ($win, $rout, $rerr, $pid) : $pid;
}

sub pipe_in {
    my $self = shift;
    $self->_check_master_and_clear_error or return ();
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my @args = $self->_quote_args(\%opts, @_);
    _croak_bad_options %opts;

    my @call = $self->_make_call([], @args);
    $debug and $debug & 16 and _debug_dump pipe_in => @call;
    my $pid = open my $rin, '|-', @call
        or return ();
    return wantarray ? ($rin, $pid) : $rin;
}

sub pipe_out {
    my $self = shift;
    $self->_check_master_and_clear_error or return ();
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my @args = $self->_quote_args(@_);
    _croak_bad_options %opts;

    my @call = $self->_make_call([], @args);
    $debug and $debug & 16 and _debug_dump pipe_out => @call;
    my $pid = open my $rout, '-|', @call
        or return ();
    return wantarray ? ($rout, $pid) : $rout;
}

sub _io3 {
    my ($self, $pid, $out, $err, $in, $stdin_data) = @_;
    $self->_check_master_and_clear_error or return ();
    my @data = (ref $stdin_data eq 'ARRAY' ? @$stdin_data : $stdin_data);
    my ($cout, $cerr, $cin) = (defined($out), defined($err), defined($in));

    my $has_input = grep { defined and length } @data;
    croak "remote input channel is not defined but data is available for sending"
        if ($has_input and !$cin);
    close $in if ($cin and !$has_input);

    my $bout = '';
    my $berr = '';
    my ($fnoout, $fnoerr, $fnoin);
    local $SIG{PIPE} = 'IGNORE';

 MLOOP: while ($cout or $cerr or $cin) {
        my ($rv, $wv);

        if ($cout or $cerr) {
            $rv = '';
            if ($cout) {
                $fnoout = fileno $out;
                vec($rv, $fnoout, 1) = 1;
            }
            if ($cerr) {
                $fnoerr = fileno $err;
                vec($rv, $fnoerr, 1) = 1
            }
        }

        if ($cin) {
            $fnoin = fileno $in;
            $wv = '';
            vec($wv, $fnoin, 1) = 1;
        }

        my $recalc_vecs;
    FAST: until ($recalc_vecs) {
            my ($rv1, $wv1) = ($rv, $wv);
            my $n = select ($rv1, $wv1, undef, $self->{timeout});
            if ($n > 0) {
                if ($cout and vec($rv1, $fnoout, 1)) {
                    my $read = sysread($out, $bout, 20480, length($bout));
                    unless ($read) {
                        close $out;
                        undef $cout;
                        $recalc_vecs = 1;
                        last unless $rv =~ /[^\x00]/;
                    }
                }
                if ($cerr and vec($rv1, $fnoerr, 1)) {
                    my $read = sysread($err, $berr, 20480, length($berr));
                    unless ($read) {
                        close $err;
                        undef $cerr;
                        $recalc_vecs = 1;
                    }
                }
                if ($cin and vec($wv1, $fnoin, 1)) {
                    my $written = syswrite($in, $data[0], 20480);
                    if ($written) {
                        substr($data[0], 0, $written, '');
                        while (@data) {
                            next FAST
                                if (defined $data[0] and length $data[0]);
                            shift @data;
                        }
                    }
                    close $in;
                    undef $cin;
                    $recalc_vecs = 1;
                }
            }
            else {
                next if ($n < 0 and $! == Errno::EINTR());
                $self->_set_error(OSSH_SLAVE_FAILED, "ssh slave failed", "timed out");
                last MLOOP;
            }
        }
    }
    close $out if $cout;
    close $err if $cerr;
    close $in if $cin;

    waitpid($pid, 0);
    return ($bout, $berr);
}

_sub_options spawn_good => qw(stderr_to_stdout stdin_fh stdout_fh
                              stderr_fh quote_args tty ssh_opts);

sub spawn {
    my $self = shift;
    my %opts =  (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    return scalar $self->open_ex(\%opts, @_);
}

_sub_options open2_good => qw(stderr_to_stdout stderr_fh
                              quote_args tty ssh_opts);
sub open2 {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($in, $out, undef, $pid) =
        $self->open_ex({ stdout_pipe => 1,
                         stdin_pipe => 1,
                         %opts }, @_) or return ();
    return ($in, $out, $pid);
}

_sub_options open2pty => qw(stderr_to_stdout stderr_fh
                            quote_args tty close_slave_pty ssh_opts);
sub open2pty {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($pty, undef, undef, $pid) =
        $self->open_ex({ stdout_pty => 1,
                         stdin_pty => 1,
                       %opts }, @_) or return ();
    return ($pty, $pid);
}

_sub_options open3 => qw(quote_args tty ssh_opts);
sub open3 {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($in, $out, $err, $pid) =
        $self->open_ex({ stdout_pipe => 1,
                         stdin_pipe => 1,
                         stderr_pipe => 1 },
                       @_) or return ();
    return ($in, $out, $err, $pid);
}

_sub_options open3pty => qw(quote_args tty close_slave_pty ssh_opts);
sub open3pty {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    _croak_bad_options %opts;

    my ($pty, undef, $err, $pid) =
        $self->open_ex({ stdout_pty => 1,
                         stdin_pty => 1,
                         stderr => 1 },
                       @_) or return ();
    return ($pty, $err, $pid);
}

_sub_options capture => qw(stderr_to_stdout stderr_fh stdin_fh quote_args tty ssh_opts);
sub capture {
    my $self = shift;

    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stdin_data = delete $opts{stdin_data};
    _croak_bad_options %opts;

    my ($in, $out, undef, $pid) =
        $self->open_ex({ stdout_pipe => 1,
                         stdin_pipe => (defined $stdin_data ? 1 : undef),
                         %opts }, @_) or return ();
    my ($output) = $self->_io3($pid, $out, undef, $in, $stdin_data);
    if (wantarray) {
        my $pattern = quotemeta $/;
        return split /(?<=$pattern)/, $output;
    }
    $output
}

_sub_options capture2 => qw(stdin_fh quote_args tty ssh_opts);
sub capture2 {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $stdin_data = delete $opts{stdin_data};
    _croak_bad_options %opts;

    my ($in, $out, $err, $pid) =
        $self->open_ex( { stdin_pipe => (defined $stdin_data ? 1 : undef),
                          stdout_pipe => 1,
                          stderr_pipe => 1,
                          %opts }, @_)
            or return ();

    $self->_io3($pid, $out, $err, $in, $stdin_data);
}

sub scp_get {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    @_ > 0 or croak
	'Usage: $ssh->scp_get(\%opts, $remote_fn1, $remote_fn2, ..., $local_fn_or_dir)';

    my $glob = delete $opts{glob};

    my $target = (@_ > 1 ? pop @_ : '.');
    $target =~ m|^[^/]*:| and $target = "./$target";

    my @src = map "$self->{_host}:$_", ( $glob
					 ? @_ 
					 : $self->_quote_args({}, @_) );

    $self->_scp(\%opts, @src, $target);
}

sub scp_put {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    @_ > 0 or croak
	'Usage: $ssh->scp_put(\%opts, $local_fn1, $local_fn2, ..., $remote_dir_or_fn)';

    my $glob = delete $opts{glob};
    my $glob_flags = ($glob ? delete $opts{glob_flags} || 0 : undef);

    my $target = "$self->{_host}:" . ( @_ > 1
				       ? $self->_quote_args({}, pop(@_))
				       : '');

    my @src = @_;
    if ($glob) {
	require File::Glob;
	@src = map File::Glob::bsd_glob($_, $glob_flags), @src;
	unless (@src) {
	    $self->_set_error(OSSH_SLAVE_SCP_FAILED,
			      "given file name patterns did not match any file");
	    return undef;
	}
    }
    $_ = "./$_" for grep m|^[^/]*:|, @src;

    $self->_scp(\%opts, @src, $target);
}


sub _scp {
    my $self = shift;
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());
    my $quiet = delete $opts{quiet};
    $quiet = 1 unless defined $quiet;
    my $recursive = delete $opts{recursive};
    my $async = delete $opts{async};

    _croak_bad_options %opts;

    my @opts;
    push @opts, '-q' if $quiet;
    push @opts, '-r' if $recursive;

    my $pid = $self->open_ex({ _scp => 1,
			       ssh_opts => \@opts,
			       quote_args => 0 },
			     @_);

    unless (defined $pid) {
	$self->_set_error(OSSH_SLAVE_SCP_FAILED,
			  "unable to spawn scp process: ".$self->error);
	return undef
    }

    return $pid if $async;

    while (1) {
	if (waitpid($pid, 0) == $pid) {
	    if ($?) {
		$self->_set_error(OSSH_SLAVE_SCP_FAILED, "scp exited with error code " . ($?>>8));
		return undef;
	    }
	    return 1;
	}
	if ($! == eval { Errno::ECHILD() }) {
	    $self->_set_error(OSSH_SLAVE_SCP_FAILED, "scp operation failed: $!");
	    return undef
	}
	
	# wait a bit before trying again
	select(undef, undef, undef, 0.1);
    }
}

sub sftp {
    my $self = shift;
    _load_module('Net::SFTP::Foreign');
    my @call = $self->_make_call([-s => 'sftp']);
    Net::SFTP::Foreign->new(open2_cmd => \@call);
}

sub mux_socket_path { shift->{_ctl_path} }

sub DESTROY {
    my $self = shift;
    my $pid = $self->{_pid};
    $debug and $debug & 2 and _debug("DESTROY($self, pid => ".(defined $pid ? $pid : undef).")");
    if ($pid) {
        local $?;
        $self->_master_ctl('exit') if defined $pid;
        waitpid($pid, 0);
    }
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::OpenSSH - Perl SSH client package implemented on top of OpenSSH

=head1 SYNOPSIS

  use Net::OpenSSH;

  my $ssh = Net::OpenSSH->new($host);
  $ssh->system("ls /tmp");

  my @ls = $ssh->capture("ls");
  my ($out, $err) = $ssh->capture2("find /root");

  my ($rin, $pid) = $ssh->pipe_in("cat >/tmp/foo");
  print $rin, "hello\n";
  close $rin;

  my ($rout, $pid) = $ssh->pipe_out("cat /tmp/foo");
  while (<$rout>) { print }
  close $rout;

  my ($in, $out ,$pid) = $ssh->open2("foo");
  my ($pty, $pid) = $ssh->open2pty("foo");
  my ($in, $out, $err, $pid) = $ssh->open3("foo");
  my ($pty, $err, $pid) = $ssh->open3pty("login");

  my $sftp = $ssh->sftp();



=head1 DESCRIPTION

Net::OpenSSH is a secure shell client package implemented on top of
OpenSSH binary client (C<ssh>).

=head2 Under the hood

This package is implemented around the multiplexing feature found in
later versions of OpenSSH. That feature allows reusing a previous SSH
connection to run new commands (I believe that OpenSSH 4.1 is the
first one to provide all the required functionality).

When a new Net::OpenSSH object is created, the OpenSSH C<ssh> client
is run in master mode stablishing a permanent (actually, for the
lifetime of the object) connection to the server.

Then, every time a new operation is requested a new C<ssh> process is
started in slave mode, effectively reusing the master SSH connection
to send the request to the remote side.

=head2 Net::OpenSSH Vs Net::SSH::.* modules

Why should you use Net::OpenSSH instead of any other of the several
Perl SSH clients available?

Well, that's my (biased) opinion:

L<Net::SSH::Perl> is not well maintained nowadays, requires a bunch of
modules (some of them very difficult to install) to be acceptably
efficient and has an API that is limited in some ways.

L<Net::SSH2> is much better than Net::SSH::Perl, but not completely
stable yet. It can be very difficult to install on some specific
operative systems and its API is also limited, in the same way as
L<Net::SSH::Perl>.

Using L<Net::SSH::Expect>, in general, is a bad idea. Handling
interaction with a shell via Expect in a generic way just can not be
reliably done.

Net::SSH is just a wrapper around any SSH binary commands available on
the machine. It can be very slow as they establish a new SSH
connection for every operation performed.

In comparison, Net::OpenSSH is a pure perl module that doesn't have
any mandatory dependencies (obviously, besides requiring OpenSSH
binaries).

Net::OpenSSH has a very perlish interface. Most operation are
performed in a fashion very similar to that or Perl builtins and
common modules (i.e. L<IPC::Open2>).

It is also very fast. The overhead introduced by launching a new ssh
process for every operation is not apreciable (at least on my Linux
box). The bottleneck is on the latency intrinsic to the protocol, so
Net::OpenSSH is probably as fast as an SSH client can be.

Being based on OpenSSH is also an advantage in several ways as a
proved, stable, secure (to paranoic levels), interoperable and well
maintained implementation of the SSH protocol is used.

On the other hand, Net::OpenSSH does not work on Windows.

Net::OpenSSH specifically requires OpenSSH SSH client (AFAIK, the
multiplexing feature is not available from any other SSH
client). Though, note that it will interacturate with any server
software, not just servers running OpenSSH C<sshd>.

For password authentication, L<IO::Pty> has to be installed. Other
modules are also required to implement specific functionality (for
instance L<Net::SFTP::Foreign> or L<Expect>).

=head1 API

Several of the methods on this package accept as first argument a
reference to a hash containing optional parameters (C<\%opts>) that
can be omitted. For instance, these two method calls are equivalent:

  my $out1 = $ssh->capture(@cmd);
  my $out2 = $ssh->capture({}, @cmd);

=head2 Error handling

Most methods return undef (or an empty list) to indicate failure.

The method C<error> can always be used to check for errors
explicitly. For instace:

  my ($output, $errput) = $ssh->capture2({timeout => 1}, "find /");
  $ssh->error and die "ssh failed: " . $ssh->error;

=head2 Net::OpenSSH methods

These are the methods provided by the package:

  *** Note that this is an early release, the ***
  *** module API has not yet stabilized!!!    ***

=over 4

=item Net::OpenSSH->new($host, %opts)

creates a new SSH master connection

C<$host> can be a hostname or and IP address. It can optionally
contain also the name of the user, her password and the TCP port
number where the server is listening:

   my $ssh1 = Net::OpenSSH->new('jack@foo.bar.com');
   my $ssh2 = Net::OpenSSH->new('jack:secret@foo.bar.com:10022');

This method always succeeds returning a new object. Error checking has
to be performed explicitly afterwards:

  my $ssh = Net::OpenSSH->new($host, %opts);
  $ssh->error and die "Can't ssh to $host: " . $ssh->error;

The accepted options are:

=over 4

=item user => $user_name

login name

=item port => $port

TCP port number where the server is running

=item passwd => $passwd

user password to use when loging on the remote side.

Note that using password authentication in automated scripts is a very
bad idea. When possible, you should use public key authentication
instead.

=item ctl_dir => $path

directory where the SSH master control socket will be created.

This directory and its parents must be writable only by the current
effective user or root, otherwise, the connection will be aborted to
avoid insecure operation.

By default C<~/.libnet-openssh-perl> is used.

=item ssh_cmd => $cmd

name or full path to OpenSSH C<ssh> binary. For instance:

  my $ssh = Net::OpenSSH->new($host, ssh_cmd => '/opt/OpenSSH/bin/ssh');

=item scp_cmd => $cmd

name or full path to OpenSSH C<scp> binary.

By default it is inferred from the C<ssh> one.

=item timeout => $timeout

maximum acceptable time that can elapse without network traffic or any
other event happening on methods that are not inmediate (for instance,
when stablishing the master SSH connection or inside C<capture>
method).

=item strict_mode => 0

by default, the connection will be aborted if the path to the socket
used for multiplexing is found to be non-secure (for instance, when
any of the parent directories is writable by other users).

This option can be used to disable that feature. Use with care!!!

=item async => 1

by default, the constructor waits until the multiplexing socket is
available. That option can be used to defer the waiting until the
socket is actually used.

For instance, the following code connects to several remote machines
in parallel:

  my (%ssh, %ls);
  for my $host (@hosts) {
      $ssh{$host} = Net::OpenSSH->new($host, async => 1);
  }
  for my $host (@hosts) {
      $ssh{$host}->system('ls /');
  }
}

=item master_opts => [...]

additional options to pass to the ssh command when stablishing the
master connection. For instance:

  my $ssh = Net::OpenSSH->new($host,
      master_opts => [-o => "ProxyCommand corkscrew httpproxy 8080 $host"]);

=back

=item $ssh->error

Returns the error condition for the last performed operation.

The returned value is a dualvar as $! (see L<perlvar/"$!">) that
renders an informative message when used on string context or an error
number on numeric context (error codes appear in
L<Net::OpenSSH::Constants>).

=item $ssh->system(@cmd)

Similar to C<system> builtin, runs the command C<@cmd> on the remote
machine using the current stdin, stdout and stderr streams for IO.

Example:

   $ssh->system('ls -R /');

The value returned also follows the C<system> builtin convention (see
L<perlvar/"$?">).

=item ($in, $out, $err, $pid) = $ssh->open_ex(\%opts, @cmd)

That method starts the command C<@cmd> on the remote machine creating
new pipes for the IO channels as specified on the C<%opts> hash.

Returns four values, the first three correspond to the local side
of the pipes created (they can be undef) and the fourth to the PID of
the new SSH slave process. An empty list is returned on failure.

Note that C<waitpid> has to be used afterwards to reap the
slave SSH process.

The accepted options are:

=over 4

=item stdin_pipe => 1

creates a new pipe and connects the reading side to the stdin stream of
the remote process. The writing side is returned as the first value.

=item stdin_pty => 1

Similar to C<stdin_pipe>, but instead of a regular pipe it uses a
pseudo-tty (pty).

Note that on some OSs (i.e. HP-UX), ttys are not reliable. They can be
overflowed when large chunks are written or when data is written
faster than it is read.

=item stdin_fh => $fh

Duplicates C<$fh> and uses it as the stdin stream of the remote process.

=item stdout_pipe => 1

Creates a new pipe and connects the writting side to the stdout stream
of the remote process. The reading side is returned as the second
value.

=item stdout_pty => 1

Connects the stdout stream of the remote process to the
pseudo-pty. This option requires C<stdin_pty> to be also set.

=item stdout_fh => $fh

Duplicates C<$fh> and uses it as the stdout stream of the remote process.

=item stderr_pipe => 1

Creates a new pipe and connects the writting side to the stderr stream
of the remote process. The reading side is returned as the third
value.

=item stderr_fh => $fh

Duplicates C<$fh> and uses it as the stderr stream of the remote process.

=item stderr_to_stdout => 1

Makes stderr point to stdout.

=item tty => $bool

Tells the remote process that it is connected to a tty.

=item close_slave_pty => 0

When a pseudo pty is used for the stdin stream, the slave side is
automatically closed on the parent process after forking the ssh
command.

This option dissables that feature, so that the slave pty can be
accessed on the parent process as C<<$pty->slave>>. It will have to be
explicitly closed (see L<IO::Pty>)

=item quote_args => $bool

See "Shell quoting" below.

=back

Usage example:

  # similar to IPC::Open2 open2 function:
  my ($in_pipe, $out_pipe, undef, $pid) = 
      $ssh->open_ex( { stdin_pipe => 1,
                       stdout_pipe => 1 },
                     @cmd )
      or die "open_ex failed: " . $ssh->error;
  # do some IO through $in/$out
  # ...
  waitpid($pid);

=item ($in, $pid) = $ssh->pipe_in(\%opts, @cmd)

This method is similar to the following Perl C<open> call

  $pid = open $in, '|-', @cmd

but running @cmd on the remote machine (see L<perlfunc/open>).

No options are currently accepted.

There is no need to perform a waitpid on the returned PID as it will
be done automatically by perl when C<$in> is closed.

Example:

  my ($in, $pid) = $ssh->pipe_in('cat >/tmp/fpp')
      or die "pipe_in failed: " . $ssh->error;
  print $in $_ for @data;
  close $in or die "close failed";

=item ($out, $pid) = $ssh->pipe_out(\%opts, @cmd)

Reciprocal to previous method, it is equivalent to

  $pid = open $out, '-|', @cmd

running @cmd on the remote machine.

No options are currently accepted.

=item ($in, $out, $pid) = $ssh->open2(\%opts, @cmd)

=item ($pty, $pid) = $ssh->open2pty(\%opts, @cmd)

=item ($in, $out, $err, $pid) = $ssh->open3(\%opts, @cmd)

=item ($pty, $err, $pid) = $ssh->open3pty(\%opts, @cmd)

Shortuts around C<open_ex> method.

=item $pid = $ssh->spawn(\%opts, @_)

Another C<open_ex> shortcut, it launches a new remote process in the
background and returns its PID.

For instance, you can run some command in several host in parallel
with the following code:

  my %conn = map { $_ => Net::OpenSSH->new($_) } @hosts;
  for my $host (@hosts) {
      open my($fh), '>', "/tmp/out-$host.txt"
        or die "unable to create file: $!;
      $conn{$host}->spawn({stdout_fh => $fh}, $cmd);
  }
  1 while wait != -1;

=item $output = $ssh->capture(\%opts, @cmd);

=item @output = $ssh->capture(\%opts, @cmd);

This method is conceptually equivalent to perl backquote operator
(i.e. C<`ls`>) running the command on the remote machine and capturing
its output.

On scalar context returns the output as an scalar. In list context
returns the output broken in lines (it honors C<$/>, see
L<perlvar/"$/">).

When an error happens while capturing (for instance, the operation
times out), the partial captured output will be returned. Error
conditions have to be explicitly checked using the C<error>
method. For instance:

  my $output = $ssh->capture({ timeout => 10 },
                             "echo hello; sleep 20; echo bye");
  $ssh->error and
      warn "operation didn't complete successfully: ". $ssh->error;
  print $output;

The accepted options are as follows:

=over 4

=item stderr_to_stdout => $bool

redirect stderr to stdout. Both streams will be captured on the same
scalar interleaved.

=item stderr_fh => $fh

attachs the remote command stderr stream to the given file handle.

=item stdin_data => $input

=item stdin_data => \@input

sends the given data to the stdin stream while simultaneously
capturing the output.

=item stdin_fh => $fh

attachs the remote command stdin stream to the given file handle.

=item timeout => $timeout

The operation is aborted after C<$timeout> seconds elapse without any
network activity.

=back

=item ($output, $errput) = $ssh->capture2(\%opts, @cmd)

captures the output sent to both stdout and stderr by C<@cmd> on the
remote machine.

The accepted options are:

=over 4

=item stdin_data => $input

=item stdin_data => @input

sends the given data to the stdin stream while simultaneously captures
the output on stdout and stderr.

=item stdin_fh => $fh

attachs the remote command stdin stream to the given file handle.

=item timeout => $timeout

The operation is aborted after C<$timeout> seconds elapse without
network activity.

=back

=item $ssh->scp_get(\%opts, $remote1, $remote2,..., $local_dir_or_file)

=item $ssh->scp_put(\%opts, $local, $local2,..., $remote_dir_or_file)

These two methods are wrappers around the C<scp> command that allow to
send and retrieve files to the remote host reusing the existant SSH
connection.

If transfer of several files is requested on the same call the latest
argument should point to an existant directory. If only one file is to
be transferred, the target argument can be omited.

Both methods return a true value when all the files are transferred
correctly, otherwise they return undef.

The accepted options are:

=over 4

=item quiet => 0

By default C<scp> is called with the quite flag C<-q> enabled in order
to suppress any progress information. This option allows to disable
scp quite feature.

=item recursive => 1

Copy files and directories recursively.

=item glob => 1

Allow expansion of shell metacharacters on the sources list.

=item glob_flags => $flags

Second argument passed to L<File::Glob> bsd_glob function. Only
available for C<scp_put> method.

=item async => 1

Doesn't wait for the C<scp> command to finish. When this option is
used the method returns the PID of the child C<scp> process.

=back

=item $sftp = $ssh->sftp

Creates a new L<Net::SFTP::Foreign> object for SFTP interaction that
runs through the ssh master connection.

=item $ssh->wait_for_master($async)

When the connection has been stablished calling the constructor with
the C<async> option, this call allows to advance the process.

If C<$async> is true, it will perform any work that can be done
inmediately without waiting (for instance, entering the password) and
then return. If a false value is given, it will finalize the
connection process and wait until the multiplexing socket is
available.

It returns a true value after the connection has been succesfully
stablished or false if the connection process fails or if it has not
yet completed (C<<$ssh->error>> can be used to differentiate between
both cases).

=item $ssh->shell_quote(@args)

return the list of arguments quoted so that they can are restored when
parsed by the remote shell.

Usually this task is done automatically by the module. See "Shell
quoting" below.

=item $ssh->mux_socket_path

Returns the path to the socket where OpenSSH listens for new
multiplexed connections.

=back

=head2 Shell quoting

By default, when invoking remote commands, this module tries to mimic
perl C<system> builtin in regard to argument processing. Quoting
L<perlfunc/system>:

  Argument processing varies depending on the number of arguments.  If
  there is more than one argument in LIST, or if LIST is an array with
  more than one value, starts the program given by the first element
  of the list with arguments given by the rest of the list.  If there
  is only one scalar argument, the argument is checked for shell
  metacharacters, and if there are any, the entire argument is passed
  to the system's command shell for parsing (this is "/bin/sh -c" on
  Unix platforms, but varies on other platforms).

Taken for example the method Net::OpenSSH C<system> method:

  $ssh->system("ls -l *");
  $ssh->system('ls', '-l', '/');

The first call passes the argument unchanged to ssh, so that it is
executed in the remote side through the user default shell that
interprets shell metacharacters.

The second call passes the arguments unchanged to the command.

Under the hood, as the Secure Shell protocol does not have provision
for this mode of operation and always spawns a new shell where it runs
the given command, Net::OpenSSH quotes any shell metacharacters in the
comand list.

All the methods that invoke a remote command (system, open_ex, etc.)
accept the option C<quote_args> that allows to force/disable shell
quoting.

For instance:

  $ssh->system({quote_args => 1}, "/path with spaces/bin/foo");

will correctly handle the spaces in the program path.

The option C<quote_args> can also be used to disable quoting when more
than one argument is passed. For instance, to get some pattern
expanded by the remote shell:

  $ssh->system({quote_args => 0}, 'ls', '-l', "/tmp/files_*.dat");

The method C<shell_quote> can be used to selectively quote some
arguments and leave others untouched:

  $ssh->system({quote_args => 0},
               $ssh->shell_quote('ls', '-l'),
               "/tmp/files_*.dat");

As shell quoting is a tricky matter, I expect bugs to pop up in this
area. You can see how C<ssh> is called, and the quoting used setting
the corresponding debug flag:

  $Net::OpenSSH::debug |= 16;

=head1 SEE ALSO

OpenSSH client documentation: L<ssh(1)>, L<ssh_config(5)>.

Core perl documentation L<perlipc>, L<perlfunc/open>,
L<perlfunc/waitpid>.

L<IO::Pty> to known how to use the pseudo tty objects returned by
several methods on this package.

L<Net::SFTP::Foreign> provides a compatible SFTP implementation.

L<Expect> can be used to interact with commands run through this module
on the remote machine.

Other Perl SSH clients: L<Net::SSH::Perl>, L<Net::SSH2>, L<Net::SSH>,
L<Net::SSH::Perl>.

=head1 BUGS AND SUPPORT

This is a very early release, expect lots of bugs. Also the API is
provisional and will be changed as required in order to improve the
module.

Does not work on Windows. OpenSSH multiplexing feature requires
passing file handles through sockets but that is not supported by
Windows.

Doesn't work on VMS either... well, actually, it probably doesn't work
on anything not resembling a modern Linux/Unix OS.

Tested on Linux and NetBSD with OpenSSH 5.1p1

To report bugs send my an email to the address that appear below or
use the L<CPAN bug tracking system|http://rt.cpan.org>.

For questions related to module usage, you can also contact my by
email but I would prefer if you post them in
L<PerlMonks|http://perlmoks.org/> (that I read frequently), so other
people can also find them.

=head1 TODO

- add expect method

- passphrase handling

- integrate with IPC::PerlSSH

Send your feature requests, ideas or any feedback, please!

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Salvador FandiE<ntilde>o (sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
