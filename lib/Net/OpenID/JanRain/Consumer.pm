package Net::OpenID::JanRain::Consumer;

=head1 JanRain Perl OpenID Consumer Library

=head2 Overview

The OpenID identity verification process most commonly uses the
following steps, as visible to the user of this library:

1. The user enters their OpenID into a field on the consumer's
site, and hits a login button.

2. The consumer site checks that the entered URL describes an
OpenID page by fetching it and looking for appropriate link
tags in the head section.

3. The consumer site sends the browser a redirect to the
identity server.  This is the authentication request as
described in the OpenID specification.

4. The identity server's site sends the browser a redirect
back to the consumer site.  This redirect contains the
server's response to the authentication request.

The most important part of the flow to note is the consumer's site
must handle two separate HTTP requests in order to perform the
full identity check.


=head3 Library Design

This consumer library is designed with that flow in mind.  The
goal is to make it as easy as possible to perform the above steps
securely.

At a high level, there are two important parts in the consumer
library.  The first important part is this module, which contains
the interface to actually use this library.  The second is the
Net::OpenID::JanRain::Stores module, which describes the
interface to use if you need to create a custom method for storing
the state this library needs to maintain between requests.

In general, the second part is less important for users of the
library to know about, as several implementations are provided
which cover a wide variety of situations in which consumers may
use the library.

This module contains a class, OpenIDConsumer, with methods
corresponding to the actions necessary in each of steps 2, 3, and
4 described in the overview.  Use of this library should be as easy
as creating an OpenIDConsumer instance and calling the methods
appropriate for the action the site wants to take.


=head3 Stores and Dumb Mode

OpenID is a protocol that works best when the consumer site is
able to store some state.  This is the normal mode of operation
for the protocol, and is sometimes referred to as smart mode.
There is also a fallback mode, known as dumb mode, which is
available when the consumer site is not able to store state.  This
mode should be avoided when possible, as it leaves the
implementation more vulnerable to replay attacks.

The mode the library works in for normal operation is determined
by the store that it is given.  The store is an abstraction that
handles the data that the consumer needs to manage between http
requests in order to operate efficiently and securely.

Several store implementation are provided, and the interface is
fully documented so that custom stores can be used as well.  See
the documentation for the OpenIDConsumer class for more
information on the interface for stores.  The concrete
implementations that are provided allow the consumer site to store
the necessary data in several different ways: in the filesystem,
in a MySQL database, or in an SQLite database.

There is an additional concrete store provided that puts the
system in dumb mode.  This is not recommended, as it removes the
library's ability to stop replay attacks reliably.  It still uses
time-based checking to make replay attacks only possible within a
small window, but they remain possible within that window.  This
store should only be used if the consumer site has no way to
retain data between requests at all.


=head3 Immediate Mode

In the flow described above, the user may need to confirm to the
identity server that it's ok to authorize his or her identity.
The server may draw pages asking for information from the user
before it redirects the browser back to the consumer's site.  This
is generally transparent to the consumer site, so it is typically
ignored as an implementation detail.

There can be times, however, where the consumer site wants to get
a response immediately.  When this is the case, the consumer can
put the library in immediate mode.  In immediate mode, there is an
extra response possible from the server, which is essentially the
server reporting that it doesn't have enough information to answer
the question yet.  In addition to saying that, the identity server
provides a URL to which the user can be sent to provide the needed
information and let the server finish handling the original
request.


=head3 Using this Library

Integrating this library into an application is usually a
relatively straightforward process.  The process should basically
follow this plan:

Add an OpenID login field somewhere on your site.  When an OpenID
is entered in that field and the form is submitted, it should make
a request to the your site which includes that OpenID URL.

When your site receives that request, it should create an
Net::OpenID::JanRain::Consumer instance, and call
its method L<"beginAuth">.  If
beginAuth completes successfully,
it will return an OpenIDAuthRequest.  Otherwise it will
provide some useful information for giving the user an error
message.

Now that you have the OpenIDAuthRequest object, you need to
preserve the value in its token
field for lookup on the user's next request from your site.  There
are several approaches for doing this which will work.  If your
environment has any kind of session-tracking system, storing the
token in the session is a good approach.  If it doesn't you can
store the token in either a cookie or in the return_to url
provided in the next step.

The next step is to call the L<"constructRedirect"> method
on the Consumer object.  Pass it the
OpenIDAuthRequest object returned by the previous call to
beginAuth along with the return_to
and trust_root URLs.  The return_to URL is the URL that the OpenID
server will send the user back to after attempting to verify his
or her identity.  The trust_root is the URL (or URL pattern) that
identifies your web site to the user when he or she is authorizing
it.

Next, send the user a redirect to the URL generated by
L<"constructRedirect">.

That's the first half of the process.  The second half of the
process is done after the user's ID server sends the user a
redirect back to your site to complete their login.

When that happens, the user will contact your site at the URL
given as the return_to URL to the
L<"constructRedirect"> call
made above.  The request will have several query parameters added
to the URL by the identity server as the information necessary to
finish the request.

When handling this request, the first thing to do is check the
openid.return_to parameter.  If it doesn't match the URL that
the request was actually sent to (the URL the request was actually
sent to will contain the openid parameters in addition to any in
the return_to URL, but they should be identical other than that),
that is clearly suspicious, and the request shouldn't be allowed
to proceed.

Otherwise, the next step is to extract the token value set in the
first half of the OpenID login.  Create a Consumer
object, and call its
L<"completeAuth"> method with that
token and a hash of all the query arguments.  This call will
return a status code and some additional information describing
the the server's response.  See the documentation for
L<"completeAuth"> for a full
explanation of the possible responses.

At this point, you have an identity URL that you know belongs to
the user who made that request.  Some sites will use that URL
directly as the user name.  Other sites will want to map that URL
to a username in the site's traditional namespace.  At this point,
you can take whichever action makes the most sense.

=cut

use warnings;
use strict;

use Carp;
use URI;

=head3 Global Constants

=over 

=item SUCCESS

This is the status code returned when either the of the
L<"beginAuth"> or L<"completeAuth"> methods return successfully.

=item HTTP_FAILURE

This is the status code L<"beginAuth"> returns when it is unable to
fetch the OpenID URL the user entered.

=item PARSE_ERROR

This is the status code L<"beginAuth">
returns when the page fetched from the entered OpenID URL doesn't
contain the necessary link tags to function as an identity page.

=item FAILURE

This is the status code L<"completeAuth">
returns when the value it received indicated an invalid login.

=item SETUP_NEEDED

This is the status code L<"completeAuth">
returns when the OpenIDConsumer instance is in immediate
mode, and the identity server sends back a URL to send the user to
to complete his or her login.

=back

=cut

use constant {
    SUCCESS      => 'success',
    FAILURE      => 'failure',
    SETUP_NEEDED => 'setup needed',
    HTTP_FAILURE => 'http failure',
    PARSE_ERROR  => 'parse error',
    };

use Net::OpenID::JanRain::Util qw(
    appendArgs
    toBase64
    fromBase64
    kvToHash
    findAgent
    );

use Net::OpenID::JanRain::CryptUtil qw(
    randomString
    hmacSha1
    sha1
    numToBase64
    base64ToNum
    numToBytes
    bytesToNum
    DH_MOD
    DH_GEN
    );

use Net::OpenID::JanRain::Consumer::LinkParser qw(parseLinkAttrs);

require Net::OpenID::JanRain::Association;
require Crypt::DH;

# Parse a query, returning the openid parameters, removing
# the 'openid.' prefix from the keys
sub getOpenIDParameters {
    my ($query) = @_;
    my %params;
    while(my ($k, $v) = each(%$query)) {
        if($k =~ m/^openid\./) {
            $params{$k} = $v;
        }
    }
    return(%params);
} # end getOpenIDParameters
########################################################################

# class/instance read/write variables
our $NONCE_LEN = 8;
our $NONCE_CHRS = join("", 'a'..'z', 'A'..'Z', 0..9);
# Maximum time for a transaction: 5 minutes
our $TOKEN_LIFETIME = 60 * 5; 

# python-style class/instance pseudo-constants:
# these can be accessed as Class->VARNAME;
# set as Class->VARNAME($val);
# but are adopted by new instances, where they become $inst->VARNAME
foreach my $var (qw(NONCE_LEN NONCE_CHRS TOKEN_LIFETIME)) {
    no strict 'refs';
    my $class = 'Net::OpenID::JanRain::Consumer';
    *{"${class}::$var"} =
        sub {
            my $self = shift;
            if(UNIVERSAL::isa($self, 'HASH')) {
                # get/set instance var
                if(@_) {
                    return($self->{$var} = $_[0]);
                }
                else {
                    return($self->{$var});
                }
            }
            elsif(ref($self)) {
                # should never get here
                die "cannot call accessor $var without class or ref\n";
            }
            else {
                # get/set class (package) var
                if(@_) {
                    return(${"${class}::$var"} = $_[0]);
                }
                else {
                    return(${"${class}::$var"});
                }
            }
        };
}

foreach my $var (qw(store immediate fetcher mode)) {
    no strict 'refs';
    my $class = 'Net::OpenID::JanRain::Consumer';
    *{"${class}::$var"} = 
        sub {
            my $self = shift;
            croak('not a hash') unless(UNIVERSAL::isa($self, 'HASH'));
            return($self->{$var});
        };
}
#######################################################################

=head2 Methods of the Net::OpenID::JanRain::Consumer

=head3 new 

Instantiate an OpenID consumer object.
You must first create a store, then call this routine with the store
instance you have created.  

=head4 Arguments

The first argument is mandatory.  The other two are optional.

=over

=item store

You must pass in an instance of an OpenID store as the first argument.

=item fetcher

You may pass in, as a second argument, an HTTP fetcher which must 
have the interface of LWP::UserAgent.

=item immediate

You may set the third argument to something which evaluates as True,
in which case the consumer object will use immediate mode.

=back

=cut

sub new {
    my $caller = shift;
    my ($store, $fetcher, $immediate) = @_;
    my $class = ref($caller) || $caller;
    unless (defined($store)) {
        die "Cannot instantiate OpenID consumer without a store";
    }
    unless($fetcher) {
    # get LWPx::ParanoidAgent if possible, otherwise LWP::UserAgent
        my $agentstring = findAgent();
        $fetcher = $agentstring->new;
    }
    my $self = {
        store     => $store,
        immediate => $immediate,
        mode      => (
            $immediate ? 'checkid_immediate' : 'checkid_setup'
            ),
        fetcher   => $fetcher,
        };
    foreach my $var (qw(NONCE_LEN NONCE_CHRS TOKEN_LIFETIME)) {
        $self->{$var} = $class->$var();
    }
    bless($self, $class);
} # end new
########################################################################

=head3 beginAuth 

This method is called to start the OpenID login process.

First, the user's claimed identity page is fetched, to
determine their identity server.  If the page cannot be
fetched or if the page does not have the necessary link tags
in it, this method returns one of HTTP_FAILURE or
PARSE_ERROR, depending on where the process failed.

Second, unless the store provided is a dumb store, it checks
to see if it has an association with that identity server, and
creates and stores one if not.

Third, it generates a signed token for this authentication
transaction, which contains a timestamp, a nonce, and the
information needed in step 4 in
the module overview.  The token is used by the library to make
handling the various pieces of information needed in step 4
easy and secure.

The token generated must be preserved until step 
4, which is after the redirect to
the OpenID server takes place.  This means that the token must
be preserved across http requests.  There are three basic
approaches that might be used for storing the token.  First,
the token could be put in the return_to URL passed into the
constructRedirect method.  Second, the token could be
stored in a cookie.  Third, in an environment that supports
user sessions, the session is a good spot to store the token.

=head4 Argument

Takes one mandatory argument.

=over

=item $user_url

The parameter $user_url is the url entered by the user as their
OpenID.  This call takes care of normalizing it and
resolving any redirects the server might issue. 

=back

=head4 Return Value

This method returns a pair of a status code and another bit of info,
as described below.

=over 

=item HTTP_FAILIURE

failed to retrieve identity page given by user.

info: the HTTP error code if we got that far, otherwise undef

=item PARSE_ERROR

we got the page, but couldn't find the link rel tag

info: undef (may change in a future release)

=item SUCCESS

info: an instance of OpenIDAuthRequest.  The 'token' attribute
of this object contains the token to be preserved for the next
HTTP request.  The 'server_url' attribute may also be useful if
you wish to whitelist or blacklist OpenID servers.  The whole
OpenIDAuthRequest object returned here must be passed to
constructRedirect.

=back

=cut

sub beginAuth {
    my $self = shift;
    my ($user_url) = @_;
    defined ($user_url) or return (FAILURE, "Bad Call");
    my ($status, $info) = $self->_findIdentityInfo($user_url);
    if($status ne SUCCESS) {
        return($status, $info);
    }
    my ($consumer_id, $server_id, $server_url) = @$info;
    my $nonce = randomString($self->NONCE_LEN, $self->NONCE_CHRS);
    my $token = $self->_genToken($nonce, $consumer_id, $server_url);
    return(SUCCESS,
        Net::OpenID::JanRain::Consumer::AuthRequest->new(
            $token, $server_id, $server_url, $nonce
            )
        );
} # end beginAuth
########################################################################

=head3 constructRedirect

This method is called to construct the redirect URL sent to
the browser to ask the server to verify its identity.  This is
called in step 3 of the flow
described in the overview.  The generated redirect should be
sent to the browser which initiated the authorization request.

=head4 Arguments

Takes three mandatory arguments.

=over 

=item $auth_req

the OpenIDAuthRequest object obtained from the call 
to beginAuth.

=item $return_to

the URL to which the user will be redirected after
visiting the OpenID server for authentication.  It must be a URL
under the trust root able to handle OpenID authentication responses.

=item $trust_root

A URL sent to the OpenID server to identify this site.
see http://www.openid.net/specs.bml for more information. While in
the spec the trust root is optional, this implementation requires it.

=back

=head4 Return Value 

The URL to which to redirect the user.

=cut

sub constructRedirect {
    my $self = shift;
    my ($auth_req, $return_to, $trust_root) = @_;
    foreach my $key (qw(server_id nonce server_url)) {
        defined($auth_req->{$key}) 
            or die "Bad OpenIDAuthRequest object";
    }
    my %redir_args = (
        'openid.identity'   => $auth_req->{server_id},
        'openid.return_to'  => $return_to,
        'openid.trust_root' => $trust_root,
        'openid.mode'       => $self->mode, # checkid_immediate in immediate mode
        );
    my $assoc = $self->_getAssociation($auth_req->{server_url}, 1);
    if($assoc) {
        $redir_args{'openid.assoc_handle'} = $assoc->{handle};
    }

    $self->store->storeNonce($auth_req->{nonce});
    return(appendArgs($auth_req->{server_url}, \%redir_args));
} # end constructRedirect
########################################################################

=head3 completeAuth

This method is called to interpret the server's response to an
OpenID request.  It is called in step
4 of the flow described in the
overview.

=head4 Arguments

Takes two mandatory arguments.

=over 

=item $token 

$token should be the token obtained from the L<"beginAuth"> call.

=item $query 

$query should be a hash reference containing the parameters on the
return to URL when the user was redirected back after visiting
the OpenID server.

=back

The return value is a pair, consisting of a status and
additional info.  The status values are strings, but
should be referred to by their symbolic values: SUCCESS,
FAILURE, and SETUP_NEEDED.

=head4 Return Value

completeAuth returns a pair of a code and info as described below.

=over 

=item SUCCESS

The second element in the return pair, info, is either undef
if the user cancelled login, or it is a string containing the
identity URL verified as belonging to the user making the request.

=item FAILIURE 

Second value as for SUCCESS.

=item SETUP_NEEDED

This code indicates that an openid.mode=immediate request
was not able to proceed immediately, and you should direct the
user to the URL contained in the second part of the return pair
if you wish to proceed with login.

=back

=cut

sub completeAuth {
    my $self = shift;
    my ($token, $query) = @_;
    my $mode = $query->{'openid.mode'};
    if($mode eq 'cancel') {
        return(SUCCESS, undef);
    }
    elsif($mode eq 'error') {
        my $error = $query->{'openid.error'};
        if($error) {
            warn "Server returned openid.error: $error";
        }
        else {
            warn "Server returned openid.mode=error with no openid.error";
        }
        return(FAILURE, undef);
    }
    elsif($mode eq 'id_res') {
        return $self->_doIdRes($token, $query);
    }
    else {
        warn "Unknown mode: $mode";
        return(FAILURE, undef)
    }
} # end completeAuth
########################################################################
sub _doIdRes {
    my $self = shift;
    my ($token, $query) = @_;
    my $ret = $self->_splitToken($token);
    return(FAILURE, ()) unless($ret and UNIVERSAL::isa($ret, 'ARRAY'));

    my ($nonce, $consumer_id, $server_url) = @$ret;

    my $return_to = $query->{'openid.return_to'};
    my $server_id = $query->{'openid.identity'};
    my $assoc_handle = $query->{'openid.assoc_handle'};

    unless($return_to and $server_id and $assoc_handle) {
        warn "Missing query args: return_to: '$return_to' server_id: '$server_id' assoc_handle: '$assoc_handle'";
        return(FAILURE, $consumer_id);
    }

    if(my $user_setup_url = $query->{'openid.user_setup_url'}) {
        return(SETUP_NEEDED, $user_setup_url);
    }

    my $assoc = $self->store->getAssociation($server_url);

    if((not $assoc) or ($assoc->{handle} ne $assoc_handle) or ($assoc->getExpiresIn == 0) ) {
        # It's not an association we know about.  Dumb mode is our
        # only possible path for recovery.
        my %check_args = getOpenIDParameters($query);
        $check_args{'openid.mode'} = 'check_authentication';

        return($self->_checkAuth($nonce, $consumer_id, \%check_args, $server_url));
    }
    # Check the signature
    my $sig = $query->{'openid.sig'};
    my $signed = $query->{'openid.signed'};
    if((not $sig) or (not $signed)) {
        warn "No signature on server response";
        return(FAILURE, $consumer_id);
    }

    my %args = getOpenIDParameters($query);
    my @signed_list = split(',', $signed);
    my $v_sig = $assoc->signHash(\%args, \@signed_list);
    if ($v_sig ne $sig) {
        warn "Signatures do not match: Received '$sig' Generated '$v_sig'";
        return(FAILURE, $consumer_id);
    }
    unless($self->store->useNonce($nonce)) {
        warn "Nonce verification failed.";
        return(FAILURE, $consumer_id);
    }
    return(SUCCESS, $consumer_id);
} # end _doIdRes
########################################################################
sub _checkAuth {
    my $self = shift;
    my ($nonce, $consumer_id, $post_data, $server_url) = @_;
    my $response = $self->fetcher->post($server_url, %$post_data);
    return(FAILURE, $consumer_id) unless($response->is_success);
    my %results = kvToHash($response->content); 

    if($results{'is_valid'}) {
        if(my $invalidate_handle = $results{'invalidate_handle'}) {
            $self->store->removeAssociation($server_url, $invalidate_handle);
        }
        return(FAILURE, $consumer_id) unless($self->store->useNonce($nonce));
        return(SUCCESS, $consumer_id);
    }
    return(FAILURE, $consumer_id) if($results{'error'});
    return(FAILURE, $consumer_id);
} # end _checkAuth
########################################################################
sub _getAssociation {
    my $self = shift;
    my ($server_url, $replace) = @_;
    $replace ||= 0;
    $self->store->isDumb and return();
    my $assoc = $self->store->getAssociation($server_url);
    unless ($assoc and $assoc->getExpiresIn > $self->{TOKEN_LIFETIME}) {
        $assoc = $self->_associate($server_url)
    }
    return $assoc;
} # end _getAssociation
########################################################################
sub _genToken {
    my $self = shift;
    my ($nonce, $consumer_id, $server_url) = @_;
    my $joined = join("\x00", time, $nonce, $consumer_id, $server_url);
    my $sig = hmacSha1($self->store->getAuthKey, $joined);
    return(toBase64($sig.$joined));
} # end _genToken
########################################################################
sub _splitToken {
    my $self = shift;
    my ($token) = @_;
    $token = fromBase64($token);
    return() if(length($token) < 20);
    my ($sig, $joined) = (substr($token, 0, 20), substr($token, 20));
    return() if(hmacSha1($self->store->getAuthKey, $joined) ne $sig);
    my @s = split(/\x00/, $joined);
    return() if(@s != 4);
    my ($timestamp, $nonce, $consumer_id, $server_url) = @s;
    return() if($timestamp == 0 or 
        (($timestamp + $self->TOKEN_LIFETIME) < time)
        );
    return([$nonce, $consumer_id, $server_url]);
} # end _splitToken
########################################################################
sub _normalizeUrl {
    my $self = shift;
    my ($url) = @_;
    defined($url) or return undef;
    $url = "http://$url" unless($url =~ m#^\w+://#);
    return(URI->new($url)->canonical);
} # end _normalizeUrl
########################################################################
sub _findIdentityInfo {
    my $self = shift;
    my ($identity_url) = @_;
    $identity_url || return (HTTP_FAILURE, undef);
    my $url = $self->_normalizeUrl($identity_url);
    my $response = $self->fetcher->get($url);
    return(HTTP_FAILURE, undef()) unless($response->is_success);
    my $consumer_id = $response->base->as_string;
    my $data = $response->content;
    ## warn "data: $data\n  ";
    my @link_attrs = parseLinkAttrs($data);
    @link_attrs or return(PARSE_ERROR, undef());
    ## warn "link_attrs:  ", keys(%{$link_attrs[1]});
    # search these for a server and delegate and take the first one
    my ($server, $delegate) = map({
            my $i = $_;
            my $f = (grep({$_->{rel} eq "openid.$i"} @link_attrs))[0];
            $f ? $f->{href} : '';
            } qw(server delegate));
    return(PARSE_ERROR, undef()) unless($server);
    return(SUCCESS, [$consumer_id,
        $delegate || $consumer_id, # server_id
        $server ]);
} # end _findIdentityInfo
########################################################################
sub _associate {
    my $self = shift;
    my ($server_url) = @_;

    my $dh = Crypt::DH->new;
    $dh->p(DH_MOD);
    $dh->g(DH_GEN);
    $dh->generate_keys;
    my $cpub = numToBase64($dh->pub_key);
    my %args = ('openid.mode', 'associate',
            'openid.assoc_type', 'HMAC-SHA1',
            'openid.session_type', 'DH-SHA1',
            'openid.dh_consumer_public', $cpub,
            );

    my $response = $self->fetcher->post($server_url, \%args);
    my $results = kvToHash($response->content);
    
    if ($response->code == 400) {
        my $error = $results->{error};
        warn "Server returned an error: " . $error;
        return undef;
    }
    elsif ($response->code != 200) {
        warn "Unexpected HTTP code " . $response->code;
        return undef;
    }

    my $assoc_type = $results->{'assoc_type'};
    unless ($assoc_type eq "HMAC-SHA1") {
        warn "Unknown assoc_type " . $assoc_type;
        return undef;
    }
    my $assoc_handle = $results->{'assoc_handle'};
    my $expires_in = int $results->{'expires_in'};
    my $session_type = $results->{'session_type'};
    my $secret;
    if (not $session_type) { # Plaintext transmission 
        $secret = fromBase64($results->{'mac_key'});
    } elsif ($session_type eq 'DH-SHA1') {
        my $spub = base64ToNum($results->{'dh_server_public'});
        my $enc_mac_key = fromBase64($results->{'enc_mac_key'});
        my $dh_secret = $dh->compute_secret($spub);
        $secret = $enc_mac_key ^ sha1(numToBytes($dh_secret));
    } else {
        warn "Bad session_type " . $session_type;
        return undef;
    }
    my $assoc = Net::OpenID::JanRain::Association->fromExpiresIn(
                $expires_in, $assoc_handle, $secret, $assoc_type);
    $self->store->storeAssociation($server_url, $assoc);
    return $assoc;
}

package Net::OpenID::JanRain::Consumer::AuthRequest;

=head2 AuthRequest

This class is instantiated by L<"beginAuth"> and is to be passed back
to the library in L<"constructRedirect">.

=head3 Properties

These can be referred to like so: C<$ar->{token}>

=over

=item token

The token, which must be saved somehow to pass back to the library in
L<"completeAuth">.

=item server_id

The user's identifier to their OpenID server.

=item server_url

The URL of the user's OpenID server

=item nonce

A nonce which protects against replay attacks.

=back

=cut

use warnings;
use strict;

sub new {
    my $caller = shift;
    my ($token, $server_id, $server_url, $nonce) = @_;
    defined ($token) or die "No token in AuthRequest constructor";
    defined ($server_id) or die "No server_id in AuthRequest constructor";
    defined ($server_url) or die "No server_url in AuthRequest constructor";
    defined ($nonce) or die "No nonce in AuthRequest constructor";
    my $class = ref($caller) || $caller;
    my $self = {
        token      => $token,
        server_id  => $server_id,
        server_url => $server_url,
        nonce      => $nonce,
        };
    bless($self, $class);
    return($self);
} # end subroutine new definition

1;
