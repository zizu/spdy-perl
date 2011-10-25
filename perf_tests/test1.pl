#!/usr/bin/perl 

use strict;
use warnings;

use Time::HiRes qw(sleep time);
use Net::SSLeay qw(get_https);
use threads;
use Thread::Queue;
use lib '../';
use SPDY::Client;

$\ = $/;
$, = "\t";
$| = 1;

for my $cnt (1, 5, map {10 * $_} 1..10) {
    print "Test on $cnt pages";
    my @res = map { sprintf "%.2f", $_ } test_search($cnt);
    print @res;
}

sub get {
    my $num = shift;
    my ($page, $result, %headers )
        = get_https('encrypted.google.com', 443, "/search?q=$num");
    return $result;
}

sub get_serial_https {
    my $num = shift;
    get($_) for 1..$num;
}

sub get_https_threads {
    my $num = shift;
    for my $i (1..$num) {
        threads->create(\&get, $num);
    }
    $_->join() for threads->list();
}

sub get_https_threads_max_6 {
    my $num = shift;
    our $tasks = Thread::Queue->new(1..$num);
    my @thread_pool = map { threads->create(\&worker_thread) }  1..6;
    $_->join() for @thread_pool;

    sub worker_thread {
        while (defined (my $task = $tasks->dequeue_nb)) {
            get($task);
        }
    }
}

sub get_https_spdy {
    my $num = shift;
    my %headers = (
            'host'    => 'encrypted.google.com',
            'method'  => 'GET',
            'scheme'  => 'https',
            'url'     => '/search?q=1',
            'version' => 'HTTP/1.1'
    );
    my $client = SPDY::Client->new('encrypted.google.com', 'https');
    my @tickets;

    for my $i (1..$num) {
        $headers{'url'} = "/search?q=$i";
        push @tickets, $client->add_stream(%headers);
    }

    sleep 0.1 while grep { not $client->is_ready($_) } @tickets;
    $client->close();
}

sub test_search {
    my $num = shift;
    my $t1 = benchmark(\&get_serial_https, $num);
    print "Serial https test complete.";
    my $t2 = benchmark(\&get_https_threads_max_6, $num);
    print "Https 6 threads test complete.";
    my $t3 = benchmark(\&get_https_threads, $num);
    print "Https unlimited threads test complete.";
    my $t4 = benchmark(\&get_https_spdy, $num);
    print "Spdy test complete.";
    return ($t1 , $t2, $t3, $t4);
}

sub benchmark {
    my $func = shift;
    my ($d, $t, $res) = (0, undef, undef);
    #for (1..10) {
        $t = time;
        $res = &$func(@_);
        $d += (time - $t);# / 10;
    #}
    return wantarray ? ($d, $res) : $d;
}
