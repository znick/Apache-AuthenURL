# $Id: AuthenURL.pm,v 0.8 1999/02/11 17:44:23 jdg117 Exp $
package Apache::AuthenURL;
use strict;
use Apache();
use Apache::Constants qw(OK SERVER_ERROR AUTH_REQUIRED);
use HTTPD::UserAdmin();
use LWP::UserAgent;
use vars qw($VERSION);

my $prefix = "Apache::AuthenURL";

$VERSION = '0.7';

my(%Config) = (
    'AuthenURL_url'		=> '',
);

sub handler {
    my($r) = @_;
    my($key,$val);
    my $attr = { };
    while(($key,$val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^AuthenURL_//;
        $attr->{$key} = $val;
    }
    
    return check($r, $attr);
}
 
sub check {
    my($r, $attr) = @_;
    my($res, $sent_pwd);
 
    ($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $user = $r->connection->user;
    my $passwd;

    unless ( $attr->{url} ) {
        $r->log_reason("$prefix is missing the URL", $r->uri);
        return SERVER_ERROR;
    }

        my $lwp_ua = new LWP::UserAgent;
        $lwp_ua->use_alarm(0);
        my $lwp_req = new HTTP::Request GET => $attr->{url};
        unless( defined $lwp_req ) {
            $r->log_reason("LWP failed to connect to URL: ".$attr->{url}, $r->uri);
            return SERVER_ERROR;
        }
        
        $lwp_req->authorization_basic($user, $sent_pwd);
        my $lwp_res = $lwp_ua->request($lwp_req);
        unless( $lwp_res->is_success ) {
            $r->log_reason("LWP user $user: " . $attr->{url} . $lwp_res->status_line, $r->uri);
            $r->note_basic_auth_failure;
            return AUTH_REQUIRED;
        }

        return OK;
    
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

 PerlSetVar AuthenURL_url https://somehost
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
 E<lt>jcbodnar@mail.utexas.eduE<gt>. 

=head1 SEE ALSO

mod_perl(1), Apache::AuthenCache(3), LWP(3)

=head1 AUTHOR

John Groenveld E<lt>groenveld@acm.orgE<gt>

=head1 COPYRIGHT

This package is Copyright (C) 1998 by John Groenveld. It may be
copied, used and redistributed under the same terms as perl itself.

=cut
