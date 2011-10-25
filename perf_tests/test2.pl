#!/usr/bin/perl 

use strict;
use warnings;

use Time::HiRes qw(sleep time);
use Net::SSLeay qw(get_https);
use threads ('exit' => 'threads_only');
use Thread::Queue;
use HTML::LinkExtor;
use URI;
use lib '../';
use SPDY::Client;

$\ = $/;
$, = "\t";
$| = 1;

for my $cnt (1, 5, map {10 * $_} 1..5) {
    print "Test on $cnt pages";
    my @res = map { sprintf "%.2f", $_ } test_search($cnt);
    print @res;
}

use constant SEARCH => '/search?q=';

sub test_search {
    my $num = shift;
    my $t1 = benchmark(\&get_serial_https, $num);
    print "Serial https test complete. Time: $t1";
    my $t2 = benchmark(\&get_https_threads_max_6, $num);
    print "Https 6 threads test complete. Time: $t2";
    my $t3 = benchmark(\&get_https_threads, $num);
    print "Https unlimited threads test complete. Time: $t3";
    my $t4 = benchmark(\&get_https_spdy, $num);
    print "Spdy test complete. Time: $t4";
    return ($t1 , $t2, $t3, $t4);
}

sub get {
    my $path = shift;
    my ($page, $result, %headers )
        = get_https('encrypted.google.com', 443, $path);

    my	$out_file_name = 2;		# output file name

        open  my $out, '>>', $out_file_name
        or die  "$0 : failed to open  output file '$out_file_name' : $!\n";

    print $out $page;

    close  $out
        or warn "$0 : failed to close output file '$out_file_name' : $!\n";

    return $page;
}

sub get_serial_https {
    my $num = shift;
    my $p = HTML::LinkExtor->new(\&callback1);

    for my $i(1..$num) {
        my $page = get(SEARCH . $i);
        $p->parse($page);
    }

    sub callback1 {
        my($tag, %attr) = @_;
        return if $tag eq 'a' || $tag eq 'form';
        if($attr{'src'} !~ /^http/) {
            get($attr{'src'});
        }
        else {
            my $u = URI->new($attr{'src'});
            get_https($u->host, $u->port, $u->path);
        }
    }
}

sub get_https_threads {
    my $num = shift;
    my $p = HTML::LinkExtor->new(\&callback2);
    my @thrs;

    for my $i (1..$num) {
        push @thrs, threads->create(\&get, SEARCH . $num);
    }

    while (grep {$_->is_running} @thrs) {
        my @joinable = grep { $_->is_joinable } @thrs;
        
        for my $thr (@joinable) {
            my $page = $thr->join();
            $p->parse($page);
        }
    }

    $_->join() for threads->list();

    sub callback2 {
        my($tag, %attr) = @_;
        return if $tag eq 'a' || $tag eq 'form';
        if($attr{'src'} !~ /^http/) {
            threads->create(\&get, $attr{'src'});
        }
        else {
            my $u = URI->new($attr{'src'});
            threads->create(\&get_https, $u->host, $u->port, $u->path);
        }
    }
}

sub get_https_threads_max_6 {
    my $num = shift;
    our $p = HTML::LinkExtor->new(\&callback3);
    our $tasks = Thread::Queue->new(map { SEARCH . $_ } 1..$num);
    my @thread_pool = map { threads->create(\&worker_thread) }  1..6;
    $_->join() for @thread_pool;

    sub worker_thread {
        while (defined (my $task = $tasks->dequeue_nb)) {
            my $resp = get($task);
            $p->parse($resp);
        }
    }

    sub callback3 {
        my($tag, %attr) = @_;
        return if $tag eq 'a' || $tag eq 'form';
        if($attr{'src'} !~ /^http/) {
            $tasks->enqueue($attr{'src'});
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
    my $p = HTML::LinkExtor->new();
    my @tickets;

    for my $i (1..$num) {
        $headers{'url'} = "/search?q=$i";
        push @tickets, $client->add_stream(%headers);
    }

    while(grep { defined } @tickets) {
        my @ready_indices = grep { $client->is_ready($tickets[$_]) } (0..$#tickets);
        my @ready = delete @tickets[@ready_indices];

        for my $ticket (@ready) {
            my $resp = $client->get($ticket);

            if($resp->is_success) {
                $p->parse($resp->decoded_content);

                for my $link ($p->links) {
                    my ($tag, %attr) = @$link;

                    next if $tag eq 'a' || $tag eq 'form';
                    if($attr{'src'} !~ /^http/) {
                        $headers{'url'} = $attr{'src'};
                        push @tickets, $client->add_stream(%headers);
                    }
                }
            }
            else {
                warn "Failed to download:" . $resp->status_line;
            }
        }
    }

    $client->close();
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

