#!/usr/bin/perl -w
use strict;
use warnings;
use Test::More tests => 64 ; # How many tests? 1+9+ 16 +29 +9 = 64
use Net::OpenID::JanRain::Server;
use Net::OpenID::JanRain::Stores::FileStore;
use Net::OpenID::JanRain::CryptUtil qw(DH_MOD DH_GEN numToBase64 base64ToNum numToBytes sha1);
use Net::OpenID::JanRain::Util qw( kvToHash toBase64 );
use URI;

my $sv_url = 'http://id.server.url/';
my $id_url = 'http://foo.com/';
my $rt_url = 'http://return.to/rt';
my $tr_url = 'http://return.to/';

my $storedir = 'testservstor';
my $store = Net::OpenID::JanRain::Stores::FileStore->new($storedir);
$store or die "Store creation failed"; # this isn't a real *server* test
my $server = Net::OpenID::JanRain::Server->new($sv_url, $store);
# 1 test
ok($server, "Server Instantiated");


sub false_cb
{
    return undef;
}

# Test errors. (9)

# 4 tests: 2-5
# getWithReturnTo 
{
    my $args = {
            'openid.mode' => 'monkeydance',
            'openid.identity' => $id_url,
            'openid.return_to' => $rt_url,
            };
    
    my ($status, $info) = $server->getOpenIDResponse('get', $args, \&false_cb);
    is($status, $server->REDIRECT, "getWithReturnTo: Redirect response");
    
    my $rt = URI->new($info);
    
    is((split /\?/, $rt->as_string)[0], $rt_url, "getWithReturnTo: return_to URL");
    my %qf = $rt->query_form;
    is($qf{'openid.mode'}, 'error', "getWithReturnTo: error mode");
    ok($qf{'openid.error'}, "getWithReturnTo: error present");
}

# 2 tests: 6-7
# getBadArgs 
{
    my $args = {
        'openid.mode' => 'zebradance',
        'openid.identity' => $id_url,
        };

    my ($status, $info) = $server->getOpenIDResponse('get', $args, \&false_cb);
    is($status, $server->LOCAL_ERROR, "getBadArgs: Error return");
    ok($info, "getBadArgs: info contains error text: $info");
}

# 1 test: 8
# getNoArgs
{
    my ($status, $info) = $server->getOpenIDResponse('get', {}, \&false_cb);
    is($status, $server->DO_ABOUT, "getNoArgs: DO_ABOUT response");
}

# 2 tests: 9-10
# test_post
{
    my $args = {
            'openid.mode' => 'pandadance',
            'openid.identity' => $id_url,
        };

    my ($status, $info) = $server->getOpenIDResponse('post', $args, \&false_cb);

    is($status, $server->REMOTE_ERROR, 'post: pandadance no good mode');
    my $result = kvToHash($info);
    ok($result->{error}, "post: error returned: $result->{error}");
}


# Association tests (16)

# 5 tests 11-16
# test_associatePlain
{
    my $args = {};
    my ($status, $info) = $server->associate($args);
    is($status, $server->REMOTE_OK, "associatePlain status");

    my $result = kvToHash($info);
    is($result->{'assoc_type'}, 'HMAC-SHA1', "associatePlain assoc_type");
    ok($result->{'assoc_handle'}, "associatePlain assoc_handle");
    ok($result->{'mac_key'}, "associatePlain plaintext secret");
    ok($result->{'expires_in'}, "associatePlain expires_in");
}

# 9 tests 17-25
# test_associateDHdefaults
{
    use Crypt::DH;
    my $dh = Crypt::DH->new(p => DH_MOD, g => DH_GEN, priv_key => 23954874);
    $dh->generate_keys;
    my $cpub = numToBase64($dh->pub_key);

    my $args = {
        'openid.session_type' => 'DH-SHA1',
        'openid.dh_consumer_public' => $cpub
        };
    my ($status, $info) = $server->associate($args);
    is($status, $server->REMOTE_OK, "associateDHdefaults status");
    my $result = kvToHash($info);
    is($result->{'assoc_type'}, 'HMAC-SHA1', "associateDHdefaults assoc_type");
    is($result->{'session_type'}, 'DH-SHA1', "associateDHdefaults session_type");
    ok($result->{'assoc_handle'}, "associateDHdefaults assoc_handle");
    ok($result->{'dh_server_public'}, "associateDHdefaults dh_server_public");
    ok((not $result->{'mac_key'}), "associateDHdefaults no plaintext secret");
    ok($result->{'expires_in'}, "associateDHdefaults expires_in");
    ok($result->{'enc_mac_key'}, "associateDHdefaults encrypted secret");
    
    my $spub = base64ToNum($result->{'dh_server_public'});
    my $enc_mac_key = $result->{'enc_mac_key'};
    my $dh_secret = $dh->compute_secret($spub);
    my $secret = sha1(numToBytes($dh_secret)) ^ $enc_mac_key;
    
    ok($secret, "associateDHdefaults secret"); # not sure this proves anything

}

# TODO: DH with non-default cyclic group

# 2 tests 26-27
# test_associateDHnoKey
{
    my $args = {'openid.session_type' => 'DH-SHA1'};

    my ($status, $info) = $server->associate($args);
    is($status, $server->REMOTE_ERROR, "associateDHnoKey status");
    my $result = kvToHash($info);
    ok($result->{'error'}, "Error returned: $result->{error}");
}


# getAuthResponse tests (29)

# 6 28-33
# test_checkidImmediateFailure
{
    my $args = {
        'openid.mode' => 'checkid_immediate',
        'openid.identity' => $id_url,
        'openid.return_to' => $rt_url,
        };

    my ($status, $info) = $server->getAuthResponse(0, $args);
    is($status, $server->REDIRECT, 'checkidImmediateFailure status');

    is((split /\?/, $info)[0], $rt_url, "checkIdImmediateFailure return_to");
    
    my $rt = URI->new($info);
    my %rtargs = $rt->query_form;
    is($rtargs{'openid.mode'}, 'id_res', 'checkidImmediateFailure mode');
    my $setup_url = $rtargs{'openid.user_setup_url'};
    my $setup_uri = URI->new($setup_url);
    my %suriargs = $setup_uri->query_form;
    is($suriargs{'openid.identity'}, $id_url, 'checkidImmediateFailure setup_url identity');
    is($suriargs{'openid.mode'}, 'checkid_setup', 'checkidImmediateFailure setup_url mode');
    is($suriargs{'openid.return_to'}, $rt_url, 'checkidImmediateFailure setup_url return_to');
}

# 8
# test_checkidImmediate
{
    my $args = {
        'openid.mode' => 'checkid_immediate',
        'openid.identity' => $id_url,
        'openid.return_to' => $rt_url,
        };

    my ($status, $info) = $server->getAuthResponse(1, $args);
    is($status, $server->REDIRECT, "checkidImmediate status");

    my $rt = URI->new($info);
    is((split /\?/, $rt->as_string)[0], $rt_url, "checkIdImmediate return_to");
    my %rtargs = $rt->query_form;

    is($rtargs{'openid.mode'}, 'id_res', "checkidImmediate mode");
    is($rtargs{'openid.identity'}, $id_url, "checkidImmediate identity");

    is($rtargs{'openid.return_to'}, $rt_url, "checkidImmediate return_to");
    is($rtargs{'openid.signed'}, 'mode,identity,return_to', "checkidImmediate signed");

    my $assoc = $store->getAssociation($server->{dumb_key}, $rtargs{'openid.assoc_handle'});
    ok($assoc, "checkidImmediate assoc_handle");
    
    my $exp = $assoc->signHash(\%rtargs, [qw(mode identity return_to)]);
    is($rtargs{'openid.sig'}, $exp, "checkidImmediate sig");
}

# 8
# test_checkIdSetup
{
    my $args = {
        'openid.mode' => 'checkid_setup',
        'openid.identity' => $id_url,
        'openid.return_to' => $rt_url,
        };

    my ($status, $info) = $server->getAuthResponse(1, $args);
    is($status, $server->REDIRECT, "checkIdSetup status");

    my $rt = URI->new($info);
    is((split /\?/, $rt->as_string)[0], $rt_url, "checkIdSetup return_to");

    my %rtargs = $rt->query_form;

    is($rtargs{'openid.mode'}, 'id_res', "checkIdSetup mode");
    is($rtargs{'openid.identity'}, $id_url, "checkIdSetup identity");

    is($rtargs{'openid.return_to'}, $rt_url, "checkIdSetup return_to");
    is($rtargs{'openid.signed'}, 'mode,identity,return_to', "checkIdSetup signed");

    my $assoc = $store->getAssociation($server->{dumb_key}, $rtargs{'openid.assoc_handle'});
    ok($assoc, "checkIdSetup assoc_handle");
    
    my $exp = $assoc->signHash(\%rtargs, [qw(mode identity return_to)]);
    is($exp, $rtargs{'openid.sig'}, "checkidImmediate sig");
}

# 3
# test_checkIdSetupNeedAuth
{
    my $args = {
        'openid.mode' => 'checkid_setup',
        'openid.identity' => $id_url,
        'openid.return_to' => $rt_url,
        'openid.trust_root' => $tr_url
        };

    my ($status, $info) = $server->getAuthResponse(0, $args);
    is($status, $server->DO_AUTH, "checkIdSetupNeedAuth status");
    is($info->trustRoot, $tr_url);
    is($info->identityURL, $id_url);
}

# 4
# test_checkIdSetupCancel
{
    my $args = {
        'openid.mode' => 'checkid_setup',
        'openid.identity' => $id_url,
        'openid.return_to' => $rt_url,
        'openid.trust_root' => $tr_url
        };

    my ($status, $info) = $server->getAuthResponse(0, $args);
    is($status, $server->DO_AUTH, "checkIdSetupCancel status1");

    ($status, $info) = $info->cancel();
    is($status, $server->REDIRECT, "checkIdSetupCancel status2");

    my $rt = URI->new($info);
    is((split /\?/, $rt->as_string)[0], $rt_url, "checkIdSetupCancel return_to");
    my %rtargs = $rt->query_form;
    is($rtargs{'openid.mode'}, 'cancel', "checkIdSetup mode");
}


# tests for CheckAuthentication (9)

# 3
# test_checkAuthentication
{
    my $args = {
            'openid.mode' => 'checkid_immediate',
            'openid.identity' => $id_url,
            'openid.return_to' => $rt_url,
            };

    my ($status, $info) = $server->getAuthResponse(1, $args);

    is($status, $server->REDIRECT, "checkAuthentication first status");

    my $rt = URI->new($info);

    my %rtargs = $rt->query_form;

    $rtargs{'openid.mode'} = 'check_authentication';

    ($status, $info) = $server->checkAuthentication(\%rtargs);
    is($status, $server->REMOTE_OK, "checkAuthentication status");
    my $result = kvToHash($info);
    is($result->{'is_valid'}, 'true', "checkAuthentication is_valid");
}

#3
# test_checkAuthenticationBadSig
{
    my $args = {
            'openid.mode' => 'checkid_immediate',
            'openid.identity' => $id_url,
            'openid.return_to' => $rt_url,
            };

    my ($status, $info) = $server->getAuthResponse(1, $args);

    is($status, $server->REDIRECT, "checkAuthenticationBadSig first status");

    my $rt = URI->new($info);

    my %rtargs = $rt->query_form;

    $rtargs{'openid.mode'} = 'check_authentication';
    $rtargs{'openid.sig'} = 'notavalidsig';

    ($status, $info) = $server->checkAuthentication(\%rtargs);
    is($status, $server->REMOTE_OK, "checkAuthenticationBadSig status");
    my $result = kvToHash($info);
    is($result->{'is_valid'}, 'false', "checkAuthenticationBadSig is_valid");

}

#3
# test_checkAuthenticationBadHandle
{
    my $args = {
            'openid.mode' => 'checkid_immediate',
            'openid.identity' => $id_url,
            'openid.return_to' => $rt_url,
            };

    my ($status, $info) = $server->getAuthResponse(1, $args);

    is($status, $server->REDIRECT, "checkAuthenticationBadHandle first status");

    my $rt = URI->new($info);

    my %rtargs = $rt->query_form;
    $rtargs{'openid.mode'} = 'check_authentication';
    $rtargs{'openid.assoc_handle'} = 'notavalidhandle';

    ($status, $info) = $server->checkAuthentication(\%rtargs);
    is($status, $server->REMOTE_OK, "checkAuthenticationBadHandle status");
    my $result = kvToHash($info);
    is($result->{'is_valid'}, 'false', "checkAuthenticationBadHandle is_valid");

}
