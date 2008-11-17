package Net::OpenSSH::Constants;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;

require Exporter;
our @ISA = qw(Exporter);
our %EXPORT_TAGS = (error => []);

my %error = ( OSSH_MASTER_FAILED => 1,
              OSSH_SLAVE_FAILED => 2,
              OSSH_PIPE_FAILED => 3
            );

for my $key (keys %error) {
    no strict 'refs';
    my $value = $error{$key};
    *{$key} = sub () { $value };
    push @{$EXPORT_TAGS{error}}, $key
}

our @EXPORT_OK = map { @{$EXPORT_TAGS{$_}} } keys %EXPORT_TAGS;

1;

__END__

=head1 NAME

Net::OpenSSH::Constants - Constant definitions for Net::OpenSSH

=head1 SYNOPSIS

  use Net::OpenSSH::Constants qw(:error);

=head1 DESCRIPTION

This module exports the following constants to be used with
L<Net::OpenSSH>: C<OSSH_MASTER_FAILED>, C<OSSH_SLAVE_FAILED>,
C<OSSH_PIPE_FAILED>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Salvador FandiE<ntilde>o (sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
