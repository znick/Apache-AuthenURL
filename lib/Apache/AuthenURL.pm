package Apache::AuthenURL;

use strict;

use vars qw{$VERSION};
$VERSION = '2.02';

use mod_perl;

# setting the constants to help identify which version of mod_perl
# is installed
use constant MP2 => ($mod_perl::VERSION >= 1.99);

# test for the version of mod_perl, and use the appropriate libraries
BEGIN {
    if (MP2) {
        require Apache::Access;
        require Apache::Connection;
        require Apache::Const;
        require Apache::Log;
        require Apache::RequestRec;
        require Apache::RequestUtil;
        Apache::Const->import(-compile => 'HTTP_UNAUTHORIZED',
                                          'HTTP_INTERNAL_SERVER_ERROR', 'OK');
    } else {
        require Apache::Constants;
        Apache::Constants->import('HTTP_UNAUTHORIZED',
                                  'HTTP_INTERNAL_SERVER_ERROR', 'OK');
    }
}

use LWP::UserAgent;

my $prefix = "Apache::AuthenURL";

my(%Config) = (
    'AuthenURL_url'		=> '',
    'AuthenURL_method'		=> '',
    'AuthenURL_proxy'		=> '',
);

sub handler {
    my($r) = @_;

    return (MP2 ? Apache::OK : Apache::Constants::OK)
        unless $r->is_initial_req;

    my($key, $val);
    my $attr = { };
    while(($key, $val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^AuthenURL_//;
        $attr->{$key} = $val;
    }
    
    return check($r, $attr);
}
 
sub check {
    my($r, $attr) = @_;
    my($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $user = MP2 ? $r->user : $r->connection->user;

    unless ( $attr->{method} ) {
        $r->warn("$prefix: missing METHOD (defaulting to GET) for URI: " .
                 $r->uri);
        $attr->{method} = "GET";
    }

    unless ( $attr->{url} ) {
        $r->log_error("$prefix is missing the URL", $r->uri);
        return MP2 ? Apache::HTTP_INTERNAL_SERVER_ERROR :
                     Apache::Constants::HTTP_INTERNAL_SERVER_ERROR;
    }

    my $lwp_ua = new LWP::UserAgent; 
    if($attr->{proxy}) {
        $lwp_ua->proxy('http', $attr->{proxy});
    }
    $lwp_ua->use_alarm(0);
    my $lwp_req = new HTTP::Request $attr->{method} => $attr->{url};
    unless( defined $lwp_req ) {
        $r->log_error("$prefix: LWP failed to use METHOD: ", $attr->{method},
                       " to connect to URL: ", $attr->{url}, $r->uri);
        return MP2 ? Apache::HTTP_INTERNAL_SERVER_ERROR :
                     Apache::Constants::HTTP_INTERNAL_SERVER_ERROR;
    }
        
    $lwp_req->authorization_basic($user, $sent_pwd);
    my $lwp_res = $lwp_ua->request($lwp_req);
    unless( $lwp_res->is_success ) {
        $r->log_error("$prefix: LWP user $user: " . $attr->{url} .
                        $lwp_res->status_line, $r->uri);
        $r->note_basic_auth_failure;
        return MP2 ? Apache::HTTP_UNAUTHORIZED :
                     Apache::Constants::HTTP_UNAUTHORIZED;
    }

    return MP2 ? Apache::OK : Apache::Constants::OK;
    
}
1;
 
__END__

=head1 NAME

Apache::AuthenURL - authenticates via another URL

=head1 SYNOPSIS

 #in .htaccess
 AuthName MyHTTPAuth
 AuthType Basic
 PerlAuthenHandler Apache::AuthenCache Apache::AuthenURL::handler Apache::AuthenCache::manage_cache

 PerlSetVar AuthenURL_method HEAD		# a valid LWP method
 PerlSetVar AuthenURL_url https://somehost
 PerlSetVar AuthenURL_proxy http://someproxy:port
 PerlSetVar AuthenCache_cache_time	

 Options Indexes FollowSymLinks ExecCGI
  
 require valid-user

=head1 DESCRIPTION

I wrote this module to work around the lack of DCE support for Solaris x86.
DCE authentication in my application is handled using Gradient's DCE
plug-in for Netscape Enterprise Server. The request is encrypted using SSL.

=head1 ACKNOWLEDGEMENTS

The cache code was heavily borrowed from Apache::AuthenDBI by Edmund Mergl
E<lt>E.Mergl@bawue.deE<gt>, but now has been stripped out in favor of the
more general solution in Apache::AuthenCache by Jason Bodnar
 E<lt>jason@shakabuku.orgE<gt>. 

=head1 SEE ALSO

mod_perl(1), Apache::AuthenCache(3), LWP(3)

=head1 AUTHOR

John Groenveld E<lt>groenveld@acm.orgE<gt>

=head1 COPYRIGHT

This package is Copyright (C) 1998 by John Groenveld. It may be
copied, used and redistributed under the same terms as perl itself.

=cut
