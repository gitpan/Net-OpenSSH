use 5.008;
use ExtUtils::MakeMaker;

WriteMakefile( NAME => 'Net::OpenSSH',
               VERSION_FROM => 'lib/Net/OpenSSH.pm',
               PREREQ_PM => { Test::More => 0, },
               AUTHOR => 'Salvador Fandino <sfandino@yahoo.com>' );
