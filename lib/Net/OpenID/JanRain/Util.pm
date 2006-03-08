package Net::OpenID::JanRain::Util;

$VERSION = "0.9.6"

use warnings;
use strict;

use Carp;
use CGI qw(-oldstyle_urls);

use MIME::Base64 qw(encode_base64);

use Exporter;

our @ISA = qw(Exporter);
our @EXPORT_OK = qw(
    log
    urlencode
    decodeParams
    appendArgs
    toBase64
    fromBase64
    kvToHash
    pairsToKV
    hashToPairs
    hashToKV
    findAgent
    );

sub log { #currently most places just use warn
    my ($message, $level) = @_;
    $level = (defined($level) ? $level : 0);
    warn $message;
} # end log
########################################################################
sub urlencode { # wrapper for the non-intuitive functionality of CGI.pm
    my %args = @_;
    return(CGI->new({%args})->query_string);
} # end subroutine urlencode definition
########################################################################
sub decodeParams {   # turns a query string into a hash
    my ($s) = @_;
    # okay for full urls
    my $c = CGI->new( ($s =~ m/^http:|\?/) ? URI->new($s)->query : $s);
    $c->param or return undef;
    return $c->Vars;
} # end subroutine decodeParams definition
########################################################################
sub appendArgs {
    my ($url, $args) = @_;
    if($args) {
        UNIVERSAL::isa($args, 'HASH') or
            croak "second arg to appendArgs must be hash ref";
        return(
            $url . (($url =~ m/\?/) ? '&' : '?') . urlencode(%$args)
            );
    }
    else {
        return($url);
    }
} # end appendArgs
########################################################################
sub toBase64 {
    my ($s) = @_;
    my $r = encode_base64($s);
    $r =~ s/\n//g;
    return $r;
} # end toBase64
########################################################################
sub fromBase64 {
    my ($s) = @_;
    return(MIME::Base64::decode_base64($s));
} # end fromBase64
########################################################################
sub kvToHash { # parses k:v\n responses
    my ($s) = @_;
    $s =~ s/^\s+|\s+$//g;
    my %form;
    foreach my $line (split(/\s*\n\s*/, $s)) {
        my ($k, $v) = split(/\s*:\s*/, $line, 2);
        $form{$k} = $v;
    }
    return(\%form);
} 
########################################################################
sub pairsToKV { # Put a list of pairs into KVform
    my ($pairs) = @_;
    
    my $kv = "";
    my $pair;
    foreach $pair (@$pairs) {
        unless (defined($pair->[0]) and defined($pair->[1])) {
            warn "pairstoKV not passed pairs";
            next;
        }
        $kv = "${kv}$pair->[0]:$pair->[1]\n";
    }
    return $kv;
}
########################################################################
# Take a hash ref and a list of keys (ref) and return a list of pairs (ref)
# the third argument is a prefix to prepend to the keys when doing
# hash lookup.
sub hashToPairs { 
    my ($hash, $keys, $prefix) = @_;
   
    my @pairs = ();
    foreach my $key (@$keys) {
        my $realkey = $prefix . $key;
        my @pair = ($key, $hash->{$realkey});
        print "No value associated with $realkey\n" unless $hash->{$realkey};
        push @pairs, \@pair;
    }
    return \@pairs;
}
########################################################################
sub hashToKV {
    my ($hashref) = @_;
    return pairsToKV(hashToPairs($hashref, [keys(%$hashref)], ''));
}
########################################################################
our $AGENT; #Save what we found for later
sub findAgent {
    $AGENT and return($AGENT);
    # try to find LWPx::ParanoidAgent
    # fall back on LWP::UserAgent
    my @agents = qw(
        LWPx::ParanoidAgent
        LWP::UserAgent
        );
    my $chooser = sub {
        my @agents = @_;
        for(my $i = 0; $i < @agents; $i++) {
            eval("use $agents[$i];");
            $@ or return($agents[$i]); # got one
            if($i < $#agents) {
                if($@ =~ m/^Can't locate/) {
                    warn("$0:  consider installing more secure $agents[$i]");
                }
                else {
                    warn("problem loading $agents[$i]:  ($@)");
                }
            }
            else {
                warn("cannot choose an agent ($@)");
            }
        }
        return();
    };
    $AGENT = $chooser->(@agents);
    $AGENT or die "No HTTP User agent found"; # Does dumb mode need an agent?
    return $AGENT;
}



1;
