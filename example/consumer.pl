#!/usr/bin/perl

use warnings;
use strict;

use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;
use CGI qw(:standard);

our $debug = 0;

my $d;

while(1) {
    $d = HTTP::Daemon->new(
            LocalPort => 8001,
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
print "Please contact me at: <URL:  ", $d->url, ">\n";


use Net::OpenID::JanRain::Consumer;
use Net::OpenID::JanRain::Stores::FileStore;
use Net::OpenID::JanRain::Util qw(appendArgs);


#O make your store
my $store = Net::OpenID::JanRain::Stores::FileStore->new('cstore');
#O and consumer
my $consumer = Net::OpenID::JanRain::Consumer->new($store);

my $this_url = $d->url;
my $trust_root = $d->url;

sub barepage {
    my ($title, $message) = @_;
    return join("\n",
        start_html(-title => $title,),
        p($message,),
        end_html,
        );
}

# setup the pages for the three steps
# all of these are called with the connection and request objects
my %post_dispatch = ( 
    '/' => sub {
        # A:
        # draw page with form name=openid_url
        my ($c, $cgi) = @_;
        my $r = $c->get_request;
        my $res = HTTP::Response->new();
        $res->content(
            join("\n",
                start_html(
                    -title => 'OpenID Example',
                    -onLoad => 'document.login.openid_url.focus()'
                    ),
                h1('OpenID Example'),
                start_form(
                    -name => 'login',
                    -method => 'get',
                    -action => '/verify',
                    ),
                'Identity URL:',
                textfield(
                    -name => 'openid_url',
                    -size => 35,
                    ),
                submit(-name => 'Verify'),
                end_form,
                end_html,
                )
            );
        $c->send_response($res);
        # user enters an openid url and clicks "Verify"
    },
    '/verify' => sub {
        # B:
        my ($c, $cgi) = @_;
        my $r = $c->get_request;
        my %query = map({$_ => $cgi->param($_)} $cgi->param()); # getQuery()
        my $openid_url = $query{'openid_url'};
        my ($status, $info) = $consumer->beginAuth($openid_url);
        my $res = HTTP::Response->new();
        if(($status eq $consumer->HTTP_FAILURE) or ($status eq $consumer->PARSE_ERROR)) {
            # errors
            if($status eq $consumer->HTTP_FAILURE) {
                $res->content(barepage("OpenID Example Failiure",
                                "Could not retrieve <q>$openid_url</q>."));
            }
            else {
                $res->content(barepage("OpenID Example Failiure",
                    "Could not find OpenID information in <q>$openid_url</q>."));
            }
            
        }
        elsif($status eq $consumer->SUCCESS) {
            # everything's okay
            $debug and warn "okay\n";
            $debug and warn "sending trust_root => $trust_root";
            my $return_to = appendArgs($this_url . 'process', {'token' => $info->{token}});
            my $redirect_url = $consumer->constructRedirect(
                $info, $return_to, $trust_root
                );

            # send user off to authenticate with their provider
            if(1) {
            $res->code(302);
            $debug and warn "loc:  ", $res->header('Location');
            $res->header(Location => $redirect_url);
            $debug and warn "cont: ", $res->header('Content-type');
            $res->content("Redirecting to $redirect_url");
            $debug and warn "dump:  ", $res->as_string;
            }
            else {
            $debug and warn "loc:  ", $res->header('Location');
            $debug and warn "cont: ", $res->header('Content-type');
            $debug and warn "dump:  ", $res->as_string;
            $res->content(barepage('OpenID Example Verification',
                            "redirect to:  $redirect_url"));
            }

        }
        else {
            die 'Not reached';
        }
        $c->send_response($res);

    },
    '/process' => sub {
        my ($c, $cgi) = @_;
        my $r = $c->get_request;
        # user goes away and comes back here
        my %query = map({$_ => $cgi->param($_)} $cgi->param()); # getQuery()
        # C:
        my $token = $query{token};
        my ($status, $info) = $consumer->completeAuth($token, \%query);
        my $openid_url = '';

        my $res = HTTP::Response->new();

        if(($status eq $consumer->FAILURE)) {
            $res->content(barepage('OpenID Example Failure',
                            "Failed to verify identity ${info}."));        
        }
        elsif($status eq $consumer->SUCCESS) {
            if($info) {
                # Success!
                $openid_url = $info;
                $res->content(barepage('OpenID Example Success',
                    "You have successfully verified $openid_url as your identity."));
            }
            else {
                $res->content(barepage('OpenID Example Failiure',
                    "Identity Verification Cancelled."));
            }
        }
        else {
           die "Bad Status '$status' from completeAuth";
        }
        $c->send_response($res);
    },
    );

########################################################################
while($conn = $d->accept) {
    while(my $r = $conn->get_request) {
        $conn->force_last_request;
        warn $r->method, " ", $r->url, "\n";
        (my $url_base = $r->url) =~ s/\?(.*)$//;
        my $params = $1 || '';
        $debug and warn "r is a $r\n";
        $debug and warn "params:  $params\n";
        my $cgi = CGI->new($params);
        # $debug and warn "r dump:  ", $r->as_string, "\n";
        # $debug and warn "r points at:  ", $r->uri, "\n";
        # $debug and warn "header dump:  ", $r->headers->as_string, "\n";
        if($r->method eq 'GET') { # Assumes that your form submits a GET
            if(exists($post_dispatch{$url_base})) {
                $post_dispatch{$url_base}->($conn, $cgi);
            }
            else {
                $conn->send_error(RC_FORBIDDEN);
            }
        }
        elsif($r->method eq 'POST') {
            $conn->send_error(RC_FORBIDDEN);
        }
        else {
            # We only do get's
            $conn->send_error(RC_FORBIDDEN);
        }
        
    }
    $conn->close;
    undef($conn);
}
