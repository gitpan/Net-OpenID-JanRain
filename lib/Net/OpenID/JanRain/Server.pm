package Net::OpenID::JanRain::Server;

=head1 Net::OpenID::JanRain::Server

This module documents the interface to the OpenID server library.  The
only part of the library which has to be used and isn't documented
here is the store for associations.  See the
Net::OpenID::JanRain::Stores module and its descendents for store
documentation.

=head2 OVERVIEW

There are two different classes of requests that identity servers
need to be able to handle.  First are the requests made directly
by identity consumers.  Second are the requests made indirectly,
via redirects sent to the user's web browser.

The first class are the requests made to it directly by identity
consumers.  These are HTTP POST requests made to the published
OpenID server URL.  There are two types of these requests, requests
to create an association, and requests to verify identity requests
signed with a secret that is entirely private to the server.

The second class are the requests made through redirects.  These
are HTTP GET requests coming from the user's web browser.  For
these requests, the identity server must perform several steps.
It has to determine the identity of the user making the request,
determine if they are allowed to use the identity requested, and
then take the correct action depending on the exact form of the
request and the answers to those questions.

=head2 LIBRARY DESIGN

This server library is designed to make dealing with both classes
of requests as straightforward as possible.

There are two parts of the library which are
important.  First, there is the OpenIDServer class in this
module.  Second, there is the Stores package, which
contains information on the necessary persistent state mechanisms,
and several implementations.

=head2 STORES

The OpenID server needs to maintain state between requests in
order to function.  Its mechanism for doing this is called a
store.  The store interface is defined in
Net::OpenID::JanRain::Stores .  Additionally, several
concrete store implementations are provided, so that most sites
won't need to implement a custom store.  For a store backed by
flat files on disk, see Net::OpenID::JanRain::Stores::FileStore .
For stores based on MySQL or SQLite, see the modules
Net::OpenID::JanRain::Stores::MySQLStore ,
Net::OpenID::JanRain::Stores::PostGreSQLStore , and
Net::OpenID::JanRain::Stores::SQLiteStore .

=head2 USING THIS LIBRARY

This library is designed to be easy to use for handling OpenID
requests.  There is, however, additional work a site has to do as
an OpenID server which is beyond the scope of this library.  That
work consists primarily of creating a couple additional pages for
handling verifying that the user wants to confirm their identity
to the consumer site.  Implementing an OpenID server using this
library should follow this basic plan:

First, you need to choose a URL to be your OpenID server URL.
This URL needs to be able to handle both GET and POST requests,
and distinguish between them.

Next, you need to have some system for mapping identity URLs to
users of your system.  The easiest method to do this is to insert
an appropriate <link> tag into your users' public pages.  See the
OpenID spec, http://openid.net/specs.bml#linkrel , for the
precise format the <link> tag needs to follow.  Then, each user's
public page URL is that user's identity URL.  There are many
alternative approaches, most of which should be fairly obvious.

The next step is to write the code to handle requests to the
server URL.  When a request comes in, several steps need to take
place:

1. Get an OpenIDServer instance with an appropriate
store.  This may be a previously created instance, or a new
one, whichever is convenient for your application.

2. Call the OpenID Server instance's L<"getOpenIDResponse">
method.  The first argument is a string indicating the HTTP
method used to make the request.  This should be either
C<'GET'> or C<'POST'>, the two HTTP methods that OpenID
uses.  The second argument is the GET or POST (as
appropriate) arguments provided for this request, as a
hash reference.  The third argument is a
callback function for determining if authentication
requests can proceed.  For more details on the callback
function, see the the documentation for
L<"getOpenIDResponse">.

3. The return value from that call is a pair, (status, info).
Depending on the status value returned, there are several
different actions you might take.  See the documentation
for the L<"getOpenIDResponse"> method for a full list
of possible results, what they mean, and what the
appropriate action for each is.

Processing all the results from that last step is fairly simple,
but it involves adding a few additional pages to your site.  There
needs to be a page about OpenID that users who visit the server
URL directly can be shown, so they have some idea what the URL is
for.  It doesn't need to be a fancy page, but there should be one.

Usually the C<DO_AUTH> case will also require at least one
page, and perhaps more.  These pages could be arranged many
different ways, depending on your site's policies on interacting
with its users.

Overall, implementing an OpenID server is a fairly straightforward
process, but it requires significant application-specific work
above what this library provides.

=head3 Global Constants

=over

=item REDIRECT
 
This status code is returned by L<"getOpenIDResponse"> when the
user should be sent a redirect.


=item DO_AUTH
 
This status code is returned by L<"getOpenIDResponse"> when the
library has determined that it's up to the application and user to
fix the reason the library isn't authorized to return a successful
authentication response.


=item DO_ABOUT

This status code is returned by L<"getOpenIDResponse"> when there
were no OpenID arguments provided at all.  This is typically the
case when somebody notices the <link> tag in a web page, wonders
what it's there for, and decides to type it in.  The standard
behavior in this case is to show a page with a small explanation
of OpenID.


=item REMOTE_OK
 
This status code is returned by L<"getOpenIDResponse"> when the
server should send a 200 response code and an exact message body.
This is for informing a remote site everything worked correctly.


=item REMOTE_ERROR
 
This status code is returned by L<"getOpenIDResponse"> when the
server should send a 400 response code and an exact message body.
This is for informing a remote site that an error occured while
processing the request.


=item LOCAL_ERROR
 
This status code is returned by
L<"getOpenIDResponse"> when
something went wrong, and the library isn't able to find an
appropriate in-protocol response.  When this happens, a short
plaintext description of the error will be provided.  The server
will probably want to return some sort of error page here, but its
contents are not strictly prescribed, like those of the
REMOTE_ERROR case.

=back

=cut

use Net::OpenID::JanRain::Util qw( appendArgs 
                                   hashToKV
                                   toBase64
                                   fromBase64
                                   );
use Net::OpenID::JanRain::CryptUtil qw( randomString
                                        numToBytes 
                                        numToBase64
                                        base64ToNum 
                                        DH_MOD
                                        DH_GEN
                                        sha1
                                        );
use Net::OpenID::JanRain::Association;
use Crypt::DH;
use constant {
    REDIRECT    =>  'redirect',
    DO_AUTH     =>  'do_auth',
    DO_ABOUT    =>  'do_about',
    REMOTE_OK   =>  'exact_ok',
    REMOTE_ERROR => 'exact_error',
    LOCAL_ERROR =>  'local_error',
    _signed_fields => 'mode,identity,return_to',
    SECRET_LIFETIME => 14 * 24 * 60 * 60 # A fortnight of seconds
};

# variable accessors
foreach my $var (qw(store url normal_key dumb_key)) {
    no strict 'refs';
    my $class = 'Net::OpenID::JanRain::Server';
    *{"${class}::$var"} = 
        sub {
            my $self = shift;
            croak('not a hash') unless(UNIVERSAL::isa($self, 'HASH'));
            return($self->{$var});
        };
}

=head2 Net::OpenID::JanRain::Server class

This class is the interface to the OpenID server logic.  Instances
contain no per-request state, so a single instance can be reused
(or even used concurrently by multiple threads) as needed.

=head2 High Level Methods

An extremely high-level interface is provided via the
C<getOpenIDResponse> method.  Implementations that wish to handle
dispatching themselves can use the low level methods described
in the next section.

=head3 new

This method initializes a new OpenID Server instance.
OpenID Server instance contain no per-request internal
state, so they can be reused or used concurrently by multiple
threads, if desired.


=head4 Arguments

=over

=item server_url

This is the server's OpenID URL.  It is
used whenever the server needs to generate a URL that will
cause another OpenID request to be made, which can happen
in authentication requests.  It's also used as part of the
key for looking up and storing the server's secrets.

=item store

This in an object implementing the
Net::OpenID::JanRain::Stores interface which
the library will use for persistent storage.  See the
Net::OpenID::JanRain::Stores
documentation for more information on stores and various
implementations.  Note that the store used for the server
must not be a dumb-style store.  It's not possible to be a
functional OpenID server without persistent storage.

=back

=cut

sub new {
    my $caller = shift;
    my ($server_url, $store) = @_;
    my $class = ref($caller) || $caller;
    die "Cannot instantiate OpenID server without a store" unless $store;
    die "OpenID servers cannot use a dumb store" if $store->isDumb;
  
    my $self = {
        url => $server_url,
        normal_key => $server_url . '|normal',
        dumb_key => $server_url . '|dumb',
        store => $store,
    };

    bless($self,$class);
}

=head3 getOpenIDResponse

This method processes an OpenID request, and determines the
proper response to it.  It then communicates what that
response should be back to its caller via return codes.


=head4 Arguments

=over

=item $http_method

This is a string describing the HTTP
method used to make the current request.  The only
expected values are 'GET' and 'POST', though
capitalization will be ignored.  Any value other than one
of the expected ones will result in a LOCAL_ERROR return
code.

=item $args

This should be a hash reference that
contains the parsed, unescaped arguments that were sent
with the OpenID request being handled. 

=item $is_authorized

This is a callback function which this
OpenIDServer instance will use to determine the
result of an authentication request.  The function will be
called with two string arguments, identity_url and
trust_root.  It should return a boolean value
indicating whether this identity request is authorized to
succeed.

The function needs to perform two seperate tasks, and
return True only if it gets a positive result from
each.

The first task is to determine the user making this
request, and if they are authorized to claim the identity
URL passed to the function.  If the user making this
request isn't authorized to claim the identity URL, the
callback should return False.

The second task is to determine if the user will allow the
trust root in question to determine his or her identity.
If they have not previously authorized the trust root to
know they're identity the callback should return False.

This callback should work only with
information already submitted, ie. the user already logged
in and the trust roots they've already approved.  It is
important that this callback does not attempt to interact
with the user.  Doing so would lead to violating the
OpenID specification when the server is handling
checkid_immediate requests.

=back

=head4 Return Codes

The return value of this method is a pair, (status, info).
The first value is the status code describing what action
should be taken.  The second value is additional information
for taking that action.

=over

=item REDIRECT

This code indicates that the server
should respond with an HTTP redirect.  In this case,
info is the URL to redirect the client to.

=item DO_AUTH

This code indicates that the server
should take whatever actions are necessary to allow
this authentication to succeed or be cancelled, then
try again.  In this case info is a
AuthorizationInfo object, which contains additional
useful information.

=item DO_ABOUT

This code indicates that the server
should display a page containing information about
OpenID.  This is returned when it appears that a user
entered an OpenID server URL directly in their
browser, and the request wasn't an OpenID request at
all.  In this case info is not defined.

=item REMOTE_OK

This code indicates that the server
should return content verbatim in response to this
request, with an HTTP status code of 200.  In this
case, info is a string containing the content to
return.

=item REMOTE_ERROR

This code indicates that the
server should return content verbatim in response to
this request, with an HTTP status code of 400.  In
this case, info is a string containing the content
to return.

=item LOCAL_ERROR

This code indicates an error that
can't be handled within the protocol.  When this
happens, the server may inform the user that an error
has occured as it sees fit.  In this case, C{info} is
a short description of the error.

=back

=cut

sub getOpenIDResponse {
    my $self = shift;
    my ($http_method, $args, $is_authorized) = @_;
    
    if (lc($http_method) eq 'get') {
        my $trust_root = ($args->{'openid.trust_root'} or
                         $args->{'openid.return_to'});
        my $id_url = $args->{'openid.identity'};
        my $authorized = 0;
        if($trust_root and $id_url) {
            $authorized = &{$is_authorized}($id_url, $trust_root);
        }
        return $self->getAuthResponse($authorized, $args);
    }
    elsif (lc($http_method) eq 'post') {
        my $mode = $args->{'openid.mode'};
        return $self->associate($args) if $mode eq 'associate';
        return $self->checkAuthentication($args) 
            if $mode eq 'check_authentication';
        return $self->postError("Invalid openid.mode ($mode) for POST request");
    }
    else {
        return (LOCAL_ERROR, 
                "HTTP method $http_method is not valid for OpenID");
    }
}

=head2 Low level methods

These methods are provided in case you must do your own dispatching for some
reason.  It is recommended that you use L<"getOpenIDResponse"> unless you have a
particular reason not to.  However, if you must do 
dispatching yourself, these methods are here to allow you to do so.

=head3 getAuthResponse

This method determines the correct response to make to an
authentication request.

This method always returns a pair.  The first value of the
pair indicates what action the server should take to respond
to this request.  The second value is additional information
to use when taking that action. (see L<"getOpenIDResponse"> for
how to handle these codes)

=head4 Arguments

=over

=item $authorized

This is a value which indicates whether the
server is authorized to tell the consumer that the user
owns the identity URL in question.  For this to be true,
the server must check that the user making this request is
the owner of the identity URL in question, and that the
user has given the consumer permission to learn his or her
identity.  The server must determine this value based on
information it already has, without interacting with the
user.  If it has insufficient information to produce a
definite affirmative, it must pass in a false value.

=item $args

This should be a hash reference that
contains the parsed, unescaped query arguments that were
sent with the OpenID request being handled.  

=back

=cut

sub getAuthResponse {
    my $self = shift;
    my ($authorized, $args) = @_;

    my $mode = $args->{'openid.mode'};

    return $self->getError($args, "Invalid openid.mode ($mode) for GET request")
        unless ($mode and 
            ($mode eq 'checkid_immediate' or $mode eq 'checkid_setup')); 
    
    my $identity = $args->{'openid.identity'} 
        or return $self->getError($args, 'No identity specified');

    my ($return_to, $error) = $self->_checkTrustRoot($args);
    return $self->getError($args, $error) if $error;

    unless ($authorized) {
        if ($mode eq 'checkid_immediate') {
            my %nargs = %$args; # deep copy
            $nargs{'openid.mode'} = 'checkid_setup';
            my $setup_url = appendArgs($self->url, \%nargs);
            my $rargs = {'openid.mode' => 'id_res', 
                         'openid.user_setup_url' => $setup_url};
            return REDIRECT, appendArgs($return_to, $rargs);
        }
        elsif ($mode eq 'checkid_setup') {
            return DO_AUTH, Net::OpenID::JanRain::Server::AuthorizationInfo->new($self->url, $args);
        }
        else {
            die "Unreachable";
        }
    }
    
    $reply = {
        'openid.mode' => 'id_res',
        'openid.return_to' => $return_to,
        'openid.identity' => $identity
        };

    my $store = $self->store;
    my $assoc_handle = $args->{'openid.assoc_handle'};
    my $assoc;
    if ($assoc_handle) {
        $assoc = $store->getAssociation($self->{normal_key}, $assoc_handle);

        # fall back to dumb mode if assoc_handle not found,
        # and send the consumer an invalidate_handle message
        if ((not $assoc) or $assoc->getExpiresIn <= 0) {
            $store->removeAssociation($self->{normal_key}, $assoc->{handle})
                if ($assoc); # remove expired association
            $assoc = $self->createAssociation('HMAC-SHA1');
            $store->storeAssociation($self->{dumb_key}, $assoc);
            $reply->{'openid.invalidate_handle'}=$assoc_handle;
        }
    }
    else {
        $assoc = $self->createAssociation('HMAC-SHA1');
        $store->storeAssociation($self->{dumb_key}, $assoc);
    }

    $reply->{'openid.assoc_handle'} = $assoc->{handle};

    $assoc->addSignature($reply, _signed_fields);

    my $url = appendArgs($return_to, $reply);
    return REDIRECT, $url;
}

=head3 associate

This method performs the openid.mode=associate
action.  Pass in the query arguments recieved as a hash ref, and
expect back a (status, info) pair.  Only the codes REMOTE_OK
and REMOTE_ERROR are returned from this method.

=cut

sub associate {
    my $self = shift;
    my ($args) = @_;

    my $assoc_type = ($args->{'openid.assoc_type'} or 'HMAC-SHA1');
    my $assoc = $self->createAssociation($assoc_type) or return
       $self->postError('unable to create an association for type $assoc_type');
    $self->store->storeAssociation($self->{normal_key}, $assoc);

    my $reply = {
        'assoc_type' => 'HMAC-SHA1',
        'assoc_handle' => $assoc->{handle},
        'expires_in' => $assoc->getExpiresIn
        };

    my $session_type = $args->{'openid.session_type'};
    if($session_type) {
        return $self->postError('session_type must be DH-SHA1')
            unless ($session_type eq 'DH-SHA1');
            
        my ($modulus, $generator);
        if (defined($args->{'openid.dh_modulus'})) {
            $modulus = base64ToNum($args->{'openid.dh_modulus'});
        } else {
            $modulus = DH_MOD;
        }
        if (defined($args->{'openid.dh_gen'})) {
            $generator = base64ToNum($args->{'openid.dh_gen'});
        } else {
            $generator = DH_GEN;
        }
        # Note: our twos complement decoder returns undef if the sign
        # bit is set, since negative numbers are invalid for us here
        return $self->postError("DH modulus and generator not positive integers")
            unless (defined($modulus) and defined($generator));
            
        return $self->postError('Missing openid.dh_consumer_public')
            unless defined($args->{'openid.dh_consumer_public'});
        my $consumer_public = $args->{'openid.dh_consumer_public'};
        my $cpub = base64ToNum($consumer_public)
            or $self->postError("DH public key must be positive integer");
        
        my $dh = Crypt::DH->new;
        $dh->p($modulus);
        $dh->g($generator);
        $dh->generate_keys;
        my $dh_secret = $dh->compute_secret($cpub);
        my $mac_key = $assoc->{secret} ^ sha1(numToBytes($dh_secret));

        $reply->{'session_type'} = $session_type;
        $reply->{'dh_server_public'} = numToBase64($dh->pub_key);
        $reply->{'enc_mac_key'} = toBase64($mac_key);
    }
    else { # no $session_type; plaintext secret transmission
        $reply->{'mac_key'} = $assoc->{secret};
    }

    return REMOTE_OK, hashToKV($reply);
}

=head3 checkAuthentication

This method performs the openid.mode=check_authentication
action.  Pass in the query arguments recieved as a hash ref, and
expect back a (status, info) pair.  Only the codes REMOTE_OK
and REMOTE_ERROR are returned from this method.

=cut

sub checkAuthentication {
    my $self = shift;
    my ($args) = @_;
    
    my $assoc_handle = $args->{'openid.assoc_handle'}
        or return $self->postError('Missing openid.assoc_handle');

    my $assoc = $self->store->getAssociation($self->{dumb_key}, $assoc_handle);

    my $reply = {};

    if ($assoc and $assoc->getExpiresIn > 0) {
        my $signed = $args->{'openid.signed'}
            or return $self->postError('Missing openid.signed');
        my $sig = $args->{'openid.sig'}
            or return $self->postError('Missing openid.sig');
        
        my %to_verify = %$args; 
        $to_verify{'openid.mode'} = 'id_res';
        my @signed_fields = split /,/, $signed; # XXX strip
        my $tv_sig = $assoc->signHash(\%to_verify, \@signed_fields);

        if ($tv_sig eq $sig) {
            $self->store->removeAssociation($self->{dumb_key}, $assoc_handle);
            $reply->{is_valid} = 'true';

            if (my $invalidate_handle = $args->{'openid.invalidate_handle'} and
                not $self->store->getAssociation($self->{normal_key},
                                                    $invalidate_handle)) {
                $reply->{invalidate_handle} = $invalidate_handle;
            }
        }
        else {
            $reply->{is_valid} = 'false';
        }
    }
    else {
        $self->store->removeAssociation($self->{dumb_key}, $assoc_handle)
            if $assoc;
        $reply->{is_valid} = 'false';
    }
    return REMOTE_OK, hashToKV($reply);
}

=head3 createAssociation

This method is used internally by the OpenID library to create
new associations to send to consumers.

=head4 Argument

=over

=item $assoc_type

The type of association to request.  Only C<'HMAC-SHA1'> is currently supported.

=back

=cut

sub createAssociation {
    my $self = shift;
    my ($assoc_type) = @_;

    return undef unless $assoc_type eq 'HMAC-SHA1';

    my $secret = randomString(20);
    my $uniq = toBase64(randomString(4));
    my $time = time;
    my $handle = "($assoc_type)($time)($uniq)";

    return Net::OpenID::JanRain::Association->fromExpiresIn(
        SECRET_LIFETIME, $handle, $secret, $assoc_type);
}

=head3 getError

This method is used to generate a correct error response
if an error occurs during a GET request.  It can return
REDIRECT, LOCAL_ERROR and DO_ABOUT codes.
        
=head4 Argument

=over

=item $args

The query arguments as a hash ref.

=item $msg

An error message to send.

=back

=cut


sub getError {
    my $self = shift;
    my ($args, $msg) = @_;

    my $return_to = $args->{'openid.return_to'};

    if($return_to) {
        my $err = {
            'openid.mode' => 'error',
            'openid.error' => $msg
            };
        return REDIRECT, appendArgs($return_to, $err);
    }
    else {
        for (keys(%$args)) {
            return LOCAL_ERROR, $msg if /^openid/;
        }
        return DO_ABOUT, undef;
    }
}

=head3 postError

Generates the correct error response if an error occurs during a POST request.
Returns the C<REMOTE_ERROR> code.

=head4 Argument

=over

=item $msg

The error message to send.

=back

=cut

sub postError {
    my $self = shift;
    my ($msg) = @_;

    return REMOTE_ERROR, "error:$msg\n";
}

sub _checkTrustRoot {
    my $self = shift;
    my ($args) = @_;

    my $return_to = $args->{'openid.return_to'};
    return undef, "No return_to URL specified" unless $return_to;
    my $trust_root = $args->{'openid.trust_root'};
    return $return_to, undef unless $trust_root;

    my $rt = URI->new($return_to);
    my $tr = URI->new($trust_root);
    
    return undef, "return_to URL invalid against trust_root: scheme"
        unless $rt->scheme eq $tr->scheme;

    # Check the host
    my $trh = $tr->host;
    if($trh =~ s/^\*\.//) { # wildcard trust root
        return undef, "return_to URL invalid against trust_root: wchost"
            unless ($rt->host =~ /\w*\.?$trh/ and $rt->port == $tr->port);
    }
    else { # no wildcard
        return undef, "return_to URL invalid against trust_root: host"
            unless $tr->host_port eq $rt->host_port;
    }
    
    # Check the path and query
    my $trp = $tr->path_query;
    return undef, "return_to URL invalid against trust_root: path"
        unless $rt->path_query =~ /^$trp/;

    # success
    return $return_to, undef;
}

1;

package Net::OpenID::JanRain::Server::AuthorizationInfo;

=head2 The AuthorizationInfo Object

This is a class to encapsulate information that is useful when
interacting with a user to determine if an authentication request
can be authorized to succeed.  This class provides methods to get
the identity URL and trust root from the request that failed.
Given those, the server can determine what needs to happen in
order to allow the request to proceed, and can ask the user to
perform the necessary actions.

The user may choose to either perform the actions or not.  If they
do, the server should try to perform the request OpenID request
again.  If they choose not to, and inform the server by hitting
some form of cancel button, the server should redirect them back
to the consumer with a notification of that for the consumer.

This class provides two approaches for each of those actions.  The
server can either send the user redirects which will cause the
user to retry the OpenID request, or it can help perform those
actions without involving an extra redirect, producing output that
works like that of C<Net::OpenID::JanRain::Server::getOpenIDResponse>.

Both approaches work equally well, and you should choose the one
that fits into your framework better.

The C<retry> and C<cancel> methods produce C<(status,
info)> pairs that should be handled exactly like the responses
from C<Net::OpenID::JanRain::Server::getOpenIDResponse>.

The C<retryURL> and C<cancelURL> methods return URLs
to which the user can be redirected to automatically retry or
cancel this OpenID request.

=cut

use Net::OpenID::JanRain::Util qw( appendArgs 
                                   hashToKV
                                   urlencode
                                   decodeParams
                                   toBase64
                                   fromBase64
                                   );
use constant {
    REDIRECT    =>  'redirect',
    DO_AUTH     =>  'do_auth',
    DO_ABOUT    =>  'do_about',
    REMOTE_OK   =>  'exact_ok',
    REMOTE_ERROR => 'exact_error',
    LOCAL_ERROR =>  'local_error',
};

=head3 new

The constructor used by the library.  It takes the base server url as a string
for the first argument and a hash ref of the query params as the second argument.

=cut

sub new {
    my $caller = shift;
    my ($server_url, $args) = @_;

    my $class = ref($caller) || $caller;

    my $self = {
      server_url => $server_url,
      identity_url => $args->{'openid.identity'},
      trust_root => ($args->{'openid.trust_root'} or $args->{'openid.return_to'}),
      args => $args,
    };

    bless $self, $class;
}

=head3 retry

This method calls L<"getOpenIDResponse"> to retry the authorization.  Provide the
server object as the first argument, and an authorization checking function
as the second argument.  This makes it easy to do a one-off authorization without
forcing the user to permit future requests from the trust_root.  After the user
is authenticated and permits the action once, simply use a function that returns
a true value as the auth checking function for $auth_info->retry.

This method returns a pair from L<"getOpenIDResponse">.

=cut

sub retry {
    my $self = shift;
    my ($openid_server, $is_authorized) = @_;
    return $openid_server->getOpenIDResponse('GET', $self->{args}, $is_authorized);
}

=head3 cancel

This method takes no arguments and returns a pair like that from 
L<"getOpenIDResponse">, but it is always a redirect to the cancel URL.
Use this when the user decides not to permit a transaction to continue.

=cut

sub cancel {
    my $self = shift;
    return REDIRECT, $self->cancelURL;
}

=head3 cancelURL

This method returns a URL to send the user to in order to cancel the OpenID
transaction.  Use this when the user decides not to permit a transaction to
continue.

=cut

sub cancelURL {
    my $self = shift;
    return appendArgs($self->{args}->{'openid.return_to'}, 
                        {'openid.mode' => 'cancel'});
}

=head3 retryURL

This method returns the original URL from whence this object came.  (The
arguments may be in different order, however.)  Use this to redirect the
user back to your site after authentication and authorization of the
transaction.

=cut

sub retryURL {
    my $self = shift;
    return appendArgs($self->{server_url}, $self->{args});
}

=head3 identityURL

Returns the identity URL that is the subject of the OpenID transaction
in question.

=cut

sub identityURL {
    my $self = shift;
    return $self->{identity_url};
}

=head3 trustRoot

Returns the trust root of the transaction.  This is a URL schema; the return
to URL must fit into this schema.  For more information see
http://openid.net/specs.bml#mode-checkid_immediate

=cut

sub trustRoot {
    my $self = shift;
    return $self->{trust_root};
}

=head3 serialize

This method returns a string that can be turned back into an AuthorizationInfo
object with the deserialize class method.

=cut

sub serialize {
    my $self = shift;
    return join '|', ($self->{server_url}, urlencode(%{$self->{args}}));
}

=head3 deserialize

This class method instantiates an AuthorizationInfo object based on a string
which must be of the form generated by serialize.

=cut

sub deserialize {
    my $caller = shift;
    my ($aistr) = @_;
    my ($server_url, $argstr) = split /\|/, $aistr;
    my $args = decodeParams($argstr);
    
    my $class = ref($caller) || $caller;

    my $self = {
      server_url => $server_url,
      identity_url => $args->{'openid.identity'},
      trust_root => ($args->{'openid.trust_root'} or $args->{'openid.return_to'}),
      args => $args,
    };

    $self->{cancel_url} = appendArgs(
        $args->{'openid.return_to'}, {'openid.mode' => 'cancel'});

    bless $self, $class;
}
    

1;
