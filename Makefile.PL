#
# Check for non-standard modules that are used by this library.
# This code was stolen from Gisle Aas' LWP
#
$| = 1;
my $missing_modules = 0;

print "Checking for HTTPD::UserAdmin......";
eval {
    require HTTPD::UserAdmin;
};
if ($@) {
    print " failed\n";
    $missing_modules++;
    print <<EOT;
$@
The HTTPD::UserAdmin module is needed to parse user information from headers.

EOT
    sleep(2);  # Don't hurry too much
} else {
    print " ok\n";
}

print "Checking for LWP......";
eval {
    require LWP::Simple;
};
if ($@) {
    print " failed\n";
    $missing_modules++;
    print <<EOT;
$@
The LWP modules is needed authenticate the user.
 
EOT
    sleep(2);  # Don't hurry too much
} else {
    print " ok\n";
}

print <<EOT if $missing_modules;
The missing modules can be obtained from CPAN.  Visit
<URL:http://www.cpan.org/> to find a CPAN site near you.

EOT

use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Apache::AuthenURL',
   DISTNAME      => 'Apache-AuthenURL',
   VERSION_FROM  => 'AuthenURL.pm',
);
