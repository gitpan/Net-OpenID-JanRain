#!/usr/bin/perl
use Net::OpenID::JanRain::CryptUtil;
use Net::OpenID::JanRain::Util;
use Net::OpenID::JanRain::Consumer;
use Net::OpenID::JanRain::Association;
use Net::OpenID::JanRain::Stores::FileStore;
use HTTP::Response;
use LWP::UserAgent; # for authenticity

package testFetcher ; # Impersonates an OpenID Server

use Net::OpenID::JanRain::Util qw( hashToPairs pairsToKV toBase64 fromBase64 );

sub user_page {
    my ($head, $body) = @_;

    $page = "<html><head><title>A User Page</title>\n $head \n</head>".
        "<body>Blah blah blah! $body </body></html>";

    return $page;
}

sub new {
    my $caller = shift;
    my ($assoc_secret, $assoc_handle) = @_;
    $ua = LWP::UserAgent->new;
    $assoc = Net::OpenID::JanRain::Association->new($assoc_handle, $assoc_secret,
                time, 3600, 'HMAC-SHA1');
    my $self = {
        assoc_secret => $assoc_secret,
        assoc_handle => $assoc_handle,
        assoc => $assoc,
        num_assocs => 0,
        ua => $ua,
        };
    bless($self);
}

$DEFAULT_DH_MOD = "155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443";
$DEFAULT_DH_GEN = 2;

$server_url = 'http://openid.example.com/';
$user_url =  'http://www.example.com/user.html';
$links = "<link rel=\"openid.server\" href=\"$server_url\" />";

$delegate_user_url = 'http://www.example.com/delegate.html';

$delegate_url = 'http://delegate.example.com/';
$delegate_links = ("<link rel=\"openid.server\" href=\"$server_url\" />".
         "<link rel=\"openid.delegate\" href=\"$delegate_url\" />");
$notlink = "rel=\"openid.server\" href=\"$server_url\"";

sub get {
    my $self = shift;
    my ($url) = @_;
    my $response;
    
    if ($url eq $user_url) { 
         $response = HTTP::Response->new(200);
         $response->content(user_page($links, ""));
    }
    elsif ($url eq 'http://not.in.a.link.tag/') {
         $response = HTTP::Response->new(200);
         $response->content(user_page($notlink, ""));
    }
    elsif ($url eq 'http://no.link.tag/') {
         $response = HTTP::Response->new(200);
         $response->content(user_page("", ""));
    }
    elsif ($url eq 'http://not.in.head/') {
         $response = HTTP::Response->new(200);
         $response->content(user_page("", $links));
    }
    elsif ($url eq $delegate_user_url) {
         $response = HTTP::Response->new(200);
         $response->content(user_page($delegate_links, ""));        
    }
    elsif ($url eq 'http://network.error/') {
        $response = $self->{ua}->get($url); # for an authentic network error
    }
    elsif ($url eq 'http://bad.request/') {
        $response = HTTP::Response->new(400, "Bad Request");
    }
    elsif ($url eq 'http://server.error/') {
        $response = HTTP::Response->new(500, "Server Error");
    }
    else {
        $response = HTTP::Response->new(404, "Not Found");
    }
    $response->header('Content-Location' => $url);
    return $response;
}

sub post {
    my $self = shift;
    my ($url, $q) = @_;

    my $response;
    if ($q->{'openid.mode'} eq 'associate') {

        ($q->{'openid.assoc_type'} eq 'HMAC-SHA1') or die "Improper openid.assoc_type";
        ($q->{'openid.session_type'} eq 'DH-SHA1') or die "Improper openid.session_type";

        $d = Crypt::DH->new;
        $d->p($q->{'openid.dh_modulus'} || $DEFAULT_DH_MOD);
        $d->g($q->{'openid.dh_gen'} || $DEFAULT_DH_GEN);
        $d->generate_keys;

        $composite = Net::OpenID::JanRain::CryptUtil::base64ToNum($q->{'openid.dh_consumer_public'});
        $enc_mac_key = toBase64($composite ^ $self->{assoc_secret});
        
        $reply = 
            "assoc_type:HMAC-SHA1"."\n".
            "assoc_handle:$self->{assoc_handle}"."\n".
            "expires_in:600"."\n".
            "session_type:DH-SHA1"."\n".
            "dh_server_public:".Net::OpenID::JanRain::CryptUtil::numToBase64($d->pub_key)."\n".
            "enc_mac_key:$enc_mac_key"."\n";

        $response = HTTP::Response->new(200);
        $response->content($reply);
        $self->{num_assocs} = $self->{num_assocs} + 1;
        return $response;
    }
    else {
        print "Post is not openid.mode=associate\n";
        print "openid.mode=".$q->{'openid.mode'}."\n";
        $response = HTTP::Response->new(400, "Bad Request");
        return $response;
    }
}

sub num_assocs {
    my $self = shift;
    return $self->{num_assocs};
}

#lets try...
sub reset_assocs {
    my $self = shift;
    $self->{num_assocs} = 0;
}

sub assoc_handle {
    my $self = shift;
    return $self->{assoc_handle};
}

package consumertest ;

$consumer_url = 'http://consumer.example.com/';

# Fix this function: remove unnecessary arguments. Clean up
sub _test_success {
    my ($user_url, $immediate) = @_;
   
    system "rm -r testfs" if -d "testfs";
    my $store = Net::OpenID::JanRain::Stores::FileStore->new('testfs');
    my $mode;
    if ($immediate) {
        $mode = 'checkid_immediate';
    } else {
        $mode = 'checkid_setup';
    }

    my $fetcher = testFetcher->new("handlepaddedto20byte", "secretshouldbe20byte");
    my $consumer = Net::OpenID::JanRain::Consumer->new($store, $fetcher, $immediate);

    sub run {
        my ($consumer) = @_;
        ($status, $info) = $consumer->beginAuth($user_url);

        $server_url = $info->{server_url};
        $server_id = $info->{server_id};
        $token = $info->{token};
        $nonce = $info->{nonce};
        
        die "$status $info" unless $status eq 'success';
        $return_to = $consumer_url;
        $trust_root = $consumer_url;
        $redirect_url = $consumer->constructRedirect($info, $return_to, $trust_root);

        #$q = #query from redirect_url
        
        #$q eq "openid.mode:$mode\n".
        #    "openid.identity:$delegate_url\n".
        #    "openid.trust_root:$trust_root\n".
        #    "openid.assoc_handle:$assoc_handle\n".
        #    "openid.return_to:$return_to\n" or die $q;

        $query = {
            'openid.mode' => 'id_res',
            'openid.return_to' => $return_to,
            'openid.identity' => $server_id,
            'openid.assoc_handle' => $fetcher->assoc_handle, 
            };

        my $assoc = $store->getAssociation($server_url, $fetcher->assoc_handle); 

        $query = $assoc->addSignature($query, "mode,return_to,identity,assoc_handle");
        
        ($status, $info) = $consumer->completeAuth($info->{token}, $query);

        ($status eq "success") or die "completeAuth Failed";
        ($info eq $user_url) or die "$info != $user_url";
    }
    ($fetcher->num_assocs == 0) || die "Wrong number of associations";
    run($consumer);
    ($fetcher->num_assocs == 1) || die "Wrong number of associations";
    # Test that we re-use the association properly
    run($consumer);
    ($fetcher->num_assocs == 1) || die "Wrong number of associations";

    # Remove the current association to test regeneration
    $store->removeAssociation($server_url, $fetcher->assoc_handle);
    run($consumer);
    ($fetcher->num_assocs == 2) || die "Wrong number of associations";
    run($consumer);
    ($fetcher->num_assocs == 2) || die "Wrong number of associations";
}

sub test_success {
    my $user_url = 'http://www.example.com/user.html';
    my $links = "<link rel=\"openid.server\" href=\"$server_url\" />";

    my $delegate_user_url = 'http://www.example.com/delegate.html';
    my $delegate_url = 'http://delegate.example.com/';
    my $delegate_links = ("<link rel=\"openid.server\" href=\"$server_url\" />".
             "<link rel=\"openid.delegate\" href=\"$delegate_url\" />");

    _test_success($user_url);
    _test_success($user_url, 1);
    _test_success($delegate_user_url);
    _test_success($delegate_user_url, 1);
}

sub test_bad_fetch {
    system "rm -r testfs" if -d 'testfs';
    my $store = Net::OpenID::JanRain::Stores::FileStore->new('testfs');

    my $fetcher = testFetcher->new($assocs[0]);

    my $consumer = Net::OpenID::JanRain::Consumer->new($store, $fetcher);
    
    my ($status, $info) = $consumer->beginAuth("http://network.error/");
    ($status eq 'http failure') or die "wrong status $status";
    defined($info) and die "Net errors don't have info like $info";
    
    my ($status, $info) = $consumer->beginAuth("http://not.found/");
    ($status eq 'http failure') or die "wrong status $status";
    defined($info) and die "Net errors don't have info like $info";
    
    my ($status, $info) = $consumer->beginAuth("http://bad.request/");
    ($status eq 'http failure') or die "wrong status $status";
    defined($info) and die "Net errors don't have info like $info";
    
    my ($status, $info) = $consumer->beginAuth("http://server.error/");
    ($status eq 'http failure') or die "wrong status $status";
    defined($info) and die "Net errors don't have info like $info";
}

sub test_bad_parse {
    system "rm -r testfs" if -d 'testfs';
    my $store = Net::OpenID::JanRain::Stores::FileStore->new('testfs');
    my $fetcher = testFetcher->new($assocs[0]);

    my $consumer = Net::OpenID::JanRain::Consumer->new($store, $fetcher);

    my ($status, $info) = $consumer->beginAuth("http://not.in.a.link.tag/");
    ($status eq 'parse error') or die "notinalinktag: wrong status $status";
    defined($info) and die "Parse errors don't have info like $info";
    my ($status, $info) = $consumer->beginAuth("http://no.link.tag/");
    ($status eq 'parse error') or die "nolinktag: wrong status $status";
    defined($info) and die "Parse errors don't have info like $info";
    my ($status, $info) = $consumer->beginAuth("http://not.in.head/");
    ($status eq 'parse error') or die "notinhead: wrong status $status";
    defined($info) and die "Parse errors don't have info like $info";
    
}

sub test_construct {
    my $oidc;
    my $pretend_store = bless({});
    my $pretend_fetcher = bless({});

    $oidc = Net::OpenID::JanRain::Consumer->new($pretend_store, $pretend_fetcher);
    ($oidc->store eq $pretend_store) or die "store not right";
    ($oidc->fetcher eq $pretend_fetcher) or die "fetcher not right";
    
    $oidc = Net::OpenID::JanRain::Consumer->new($pretend_store, $pretend_fetcher, 1);
    ($oidc->store eq $pretend_store) or die "store not right";
    ($oidc->fetcher eq $pretend_fetcher) or die "fetcher not right";
    $oidc->{immediate} or die "Not immediate";

    $oidc = Net::OpenID::JanRain::Consumer->new($pretend_store);
    $oidc->fetcher->can('get') or die "default fetcher can't get";
    $oidc->fetcher->can('post') or die "default fetcher can't post";
    
    eval { Net::OpenID::JanRain::Consumer->new(); } and die "instantiated consumer without store";
    
}

test_bad_fetch();
test_bad_parse();
test_success();
test_construct();
exit(0);
