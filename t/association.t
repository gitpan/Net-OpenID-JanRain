#!/usr/bin/perl
use Net::OpenID::JanRain::Association;

my @assoc_keys = (
        'version',
        'handle',
        'secret',
        'issued',
        'lifetime',
        'assoc_type',
        );

$issued = time;
$lifetime = 600;
$assoc = Net::OpenID::JanRain::Association->new(
        'handle', 'secret', $issued, $lifetime, 'HMAC-SHA1');
$s = $assoc->serialize();
$assoc2 = Net::OpenID::JanRain::Association->deserialize($s);
for $k (@assoc_keys) {
    $v1 = $assoc->{$k};
    $v2 = $assoc2->{$k};
    print "$k : $v1 : $v2\n";
}

exit(0) if $assoc->equals($assoc2);

die "Association serialization/deserialization test failed"

