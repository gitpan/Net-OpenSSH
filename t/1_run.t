#!/usr/bin/perl

use strict;
use warnings;
use Cwd;

use Test::More;

use Net::OpenSSH;

my $V = `ssh -V 2>&1`;
my ($ver, $num) = $V =~ /^(OpenSSH_(\d+\.\d+).*)$/msi;

plan skip_all => 'OpenSSH 4.1 or later required'
    unless (defined $num and $num >= 4.1);

chomp $ver;
diag "\nSSH client found: $ver\nTrying to connect to localhost, timeout is 30s.\n";

my $ssh = Net::OpenSSH->new('localhost', timeout => 30);

plan skip_all => 'Unable to establish SSH connection to localhost'
    if $ssh->error;

plan tests => 15;

sub shell_quote {
    my $txt = shift;
    $txt =~ s|([^a-zA-Z0-9+-\./])|\\$1|g;
    $txt
}

my $cwd = cwd;
my $sq_cwd = shell_quote $cwd;

my @ls_good= `ls $sq_cwd`;
my @ls = $ssh->capture({stderr_to_stdout => 1}, "ls $sq_cwd");
is("@ls", "@ls_good");

my @lines = map "foo $_\n", 1..10;
my $lines = join('', @lines);

my ($in, $pid) = $ssh->pipe_in("cat > $sq_cwd/test.dat");
ok($ssh->error == 0);
ok($in);
ok(defined $pid);

print $in $_ for @lines;
my @ps = `ps p $pid`;
ok(grep(/ssh/i, @ps));
ok(close $in);
@ps = `ps p $pid`;
ok(!grep(/ssh/i, @ps));

ok(-f "$cwd/test.dat");

my ($output, $errput) = $ssh->capture2("cat $sq_cwd/test.dat");
is($errput, '', "errput");
is($output, $lines, "output") or diag $output;

$output = $ssh->capture({stdin_data => \@lines}, "cat");
is ($output, $lines);

($output, $errput) = $ssh->capture2("cat $sq_cwd/test.dat 1>&2");
is ($errput, $lines);
is ($output, '');

my $string = q(#@$#$%&(@#_)erkljgfd'' 345345' { { / // ///foo);

$output = $ssh->capture(echo => $string);
chomp $output;
is ($output, $string, "quote_args");

eval { $ssh->capture({foo => 1}, 'bar') };
ok($@ =~ /option/ and $@ =~ /foo/);
