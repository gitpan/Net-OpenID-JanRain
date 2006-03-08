#!/usr/bin/perl

use warnings;
use strict;

use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;

# Probably should just pick one of URI/CGI.
use URI;
use URI::QueryParam;
use CGI;

our $debug = 0;

my $d;

while(1) {
    $d = HTTP::Daemon->new(
            LocalPort => 8008,
            ReuseAddr => 1,
            );
    unless($d) {
        warn;
        sleep(1);
    }
    else {
        $d and last;
    }
}

my $conn;
$SIG{INT} = $SIG{HUP} = sub {
    my ($sig) = @_;
    print "signal $sig caught\n";
    if($conn) {
        $conn->close;
        undef($conn);
    }
    else {
        warn "no connection!\n";
    }
    undef($d);
    exit;
};
print "Example OpenID server running at: <URL:  ", $d->url, ">\n";

use Net::OpenID::JanRain::Server;
use Net::OpenID::JanRain::Stores::FileStore;
use Net::OpenID::JanRain::Util;


# We'll need a store.
my $store = Net::OpenID::JanRain::Stores::FileStore->new('sstore');

# The server needs to know the URL handled by getOpenIDResponse
my $serverurl = $d->url."openidserver";

# And a server.
my $server = Net::OpenID::JanRain::Server->new($serverurl, $store);

# keep record of what's permitted
my %allowed = ();

########################################################################
while($conn = $d->accept) {
    while(my $r = $conn->get_request) {
        $conn->force_last_request;
        warn $r->method, " ", $r->url, "\n";
      
        my $uri = URI->new($r->url);
        my $res;

        if ($r->method eq 'POST') {
            print $r->content;
        }

        if ($uri->path eq '/openidserver') {
            my $query;
            if($r->method eq 'GET') {
                $query = $uri->query_form_hash
            }
            else { # assume POST
                my $cgi = CGI->new($r->content);
                $query = $cgi->Vars;
            }
            my ($status, $info) = $server->getOpenIDResponse($r->method,
                                                        $query,
                                                        \&authChecker);
            warn "$status $info";
            $res = handleOpenIDReturn($status, $info);
        }
        elsif ($uri->path =~ m:^/id/(\w+): ) {
            $res = identityPage($1);
        }
        elsif ($uri->path eq '/auth' and $r->method eq 'POST') {
            my $cgi = CGI->new($r->content);
            my $query = $cgi->Vars;
            $res = handleAuth($query);
        }
        else {
            $res = HTTP::Response->new;
            $res->code(404);
            $res->content(errorPage("Not Found."));
        }
        $conn->send_response($res);
    }
    $conn->close;
    undef($conn);
}

sub handleOpenIDReturn {
    my ($status, $info) = @_;
    my $res;
    if($status eq $server->REDIRECT) {
        $res = HTTP::Response->new(302);
        $res->header(Location => $info);
        $res->content("Redirecting to $info");
    }
    elsif($status eq $server->DO_AUTH) {
        $res = authenticationPage($info);
    }
    elsif($status eq $server->DO_ABOUT) {
        $res = aboutPage();
    }
    elsif($status eq $server->REMOTE_OK) {
        $res->content($info);
    }
    elsif($status eq $server->REMOTE_ERROR) {
        $res = HTTP::Response->new(400);
        $res->content($info);
    }
    elsif($status eq $server->LOCAL_ERROR) {
        $res = errorPage($info);
    }
    else {
        die "Should be unreachable. status='$status'";
    }
    return $res;
}

sub handleAuth {
    my ($form) = @_;
    my $auth_info = Net::OpenID::JanRain::Server::AuthorizationInfo->deserialize($form->{auth_info});
    
    # Clearly in a real app you'll want something more sophisticated here
    my $permit = $form->{yes};
    
    my $id_url = $auth_info->identityURL;
    my $trust_root = $auth_info->trustRoot;
    
    if($permit) {
        if($form->{remember}) {
            my $k = "$id_url $trust_root";
            $allowed{$k} = 1;
        }
        return handleOpenIDReturn($auth_info->retry($server, \&authPermitter));
    }
    else {
        return handleOpenIDReturn($auth_info->cancel);
    }
}

sub authChecker {
    my ($id_url, $trust_root) = @_;
    my $k = "$id_url $trust_root";
    return $allowed{$k};
}

sub authPermitter {
    return 1;
}

sub identityPage {
    my ($user) = @_;
    my $page = join("\n", "<html><head><title>Example Identity page for $user</title>",
        "<link rel=openid.server href=$serverurl > </head>",
        "<body><h1>OpenID Server Example<h1>",
        "<h2>Identity page for $user</h2>",
        "This page contains a link tag that shows that the owner of this",
        "URL uses this OpenID server. </body></html>");
    my $res = HTTP::Response->new(200);
    $res->content($page);
    return $res;
}

sub authenticationPage {
    my ($authinfo) = @_;
    my $trust_root = $authinfo->trustRoot;
    my $identity = $authinfo->identityURL;
    my $cereal = $authinfo->serialize;
    my $res = HTTP::Response->new(200);
    $res->content(join("\n",
        "<html><head><title>OpenID Example Auth Page</title><head>",
        "<body><h1>OpenID Example Auth Page</h1>",
        "<p>A site has asked for your identity.  If you",
        "approve, the site represented by the trust root below will",
        "be told that you control identity URL listed below. (If",
        "you are using a delegated identity, the site will take",
        "care of reversing the delegation on its own.)</p>",
        "<p>This being a simple example, we don't do logins.",
        "In a real application, this page would verify that",
        "the user is who they are claiming to be.</p>",
        "<h2>Permit this authentication?</h2>",
        "<table>",
        "<tr><td>Identity:</td><td>$identity</td></tr>",
        "<tr><td>Trust Root:</td><td>$trust_root</td></tr>",
        "</table>",
        "<form method='POST' action='/auth'>",
        "<input type='hidden' name='auth_info' value='$cereal' />",
        "<input type='checkbox' id='remember' name='remember' value='yes'",
        'checked="checked" /><label for="remember">Remember this decision',
        "</label><br>",
        '<input type="submit" name="yes" value="yes" />',
        '<input type="submit" name="no" value="no" /></form>',
        "</body></html"
        ));
    return $res;
}

sub aboutPage {
    my $res = HTTP::Response->new(200);
    $res->content(join("\n", 
        "<html><head><title>Example OpenID Server Endpoint</title></head>",
        "<body><h1>Example OpenID About Page</h1>",
        "<p>This page is for when the Server endpoint is visited with no",
        "query arguments, suggesting that someone entered in the URL by",
        "hand.  Render a short description such as the following:</p>",
        "<p>This is an OpenID server endpoint, not a human readable",
        "resource.  For more information about openid, try ",
        "<a href='http://www.openidenabled.com/'>this page</a>.</p>",
        "</body></html>"));
    return $res;
}

sub errorPage {
    my ($msg) = @_;
    my $res = HTTP::Response->new(400);
    $res->content(join("\n", 
        "<html><head><title>Example OpenID Server Error Page</title></head>",
        "<body><h1>OpenID Example Server Error<h1>",
        "<p>$msg</p>",
        "</body></html>"));
}
