#!/usr/bin/perl 

use strict;
use warnings;
use Time::HiRes qw(sleep);
use SPDYClient;

my %headers = (
    'host'    => 'encrypted.google.com',
    'method'  => 'GET',
    'scheme'  => 'https',
    'url'     => '/',
    'version' => 'HTTP/1.1'
);

my $client = SPDYConnection->new('encrypted.google.com', 'https');
my $ticket = $client->add_stream(%headers);
sleep 0.1 while not $client->is_ready($ticket);
my $resp =  $client->get($ticket);
if($resp->is_success) {
   print $resp->decoded_content();
}
else {
    print %$resp;
}
$client->close;
