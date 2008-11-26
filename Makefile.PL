use 5.006;

use ExtUtils::MakeMaker;

WriteMakefile( NAME => 'Net::OpenSSH',
               VERSION_FROM => 'lib/Net/OpenSSH.pm',
               PREREQ_PM => { Test::More => 0, },
               AUTHOR => 'Salvador Fandino <sfandino@yahoo.com>' );

$^O =~ /Win32|cygwin/
    and die "Net::OpenSSH does not work on Windows, sorry!\naborting...\n";

