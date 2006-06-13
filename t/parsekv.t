#!/usr/bin/perl

use Net::OpenID::JanRain::Util qw(parsekv);

use strict;
use warnings;

use Test::More qw(
	no_plan
	);

my @list = (
[
"a:b"
=> {qw(a b)}
],
[
"a:b
c:d"
=> {qw(a b c d)}
],
[
"
a:b
c:d

"
=> {qw(a b c d)}
],
[
"a  :   b  
  c: d 
 e	:  	f
 	"
=> {qw(a b c d e f)}
],
	);

foreach my $item (@list) {
	is_deeply({parsekv($item->[0])}, $item->[1]);
}

