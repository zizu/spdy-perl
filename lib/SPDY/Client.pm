package SPDY::Client;

use 5.10.0;
use strict;
use warnings;

use Socket;
use URI;
use HTTP::Response;
use HTTP::Headers;
use Time::HiRes qw(sleep);
use SPDY::Protocol;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use threads ('exit' => 'threads_only');
use threads::shared qw(share is_shared shared_clone);

use constant {
    DATA       => 0,
               SYN_STREAM => 1,
               SYN_REPLY  => 2,
               RST_STREAM => 3,
               SETTINGS   => 4,
               NOOP       => 5,
               PING       => 6,
               GOAWAY     => 7,
               HEADERS    => 8,

               FLAG_FIN            => 1,
               FLAG_UNIDIRECTIONAL => 2,

               DATA_SIZE => 1325,
};

require Exporter;
use AutoLoader qw(AUTOLOAD);

our @ISA = qw(Exporter);

our $VERSION = '0.04';

sub new {
    my ($class, $host, $scheme, $port) = @_;

    return undef if not defined $host;
    if(not defined $scheme) {
        my $uri = URI->new($host);
        $scheme = $uri->scheme || return undef;
        $host   = $uri->host;
        $port   = $uri->port;
    }
    elsif(not defined $port) {
        $port = $scheme eq 'http' ? 80 : 443 ;
    }

    my $fields = {
        'host'        => $host,
        'scheme'      => $scheme,
        'stream_no'   => 1,
        'stream_data' => [],
        'repls'       => shared_clone([]),
        'protocol'    => SPDYv2Protocol->new,
        'port'        => $port,
    };

    my $self = bless ($fields, $class);
    $self->_connect() or return undef;
    threads->create('SPDY::Client::_recv', $self)->detach;

    return $self;
}

sub add_stream {
    my $self = shift;
    my $req  = shift;
    my (%headers, $content, $frame);

    if (ref $req eq 'HTTP::Request') {
        my $uri = URI->new($req->uri);

        %headers = (
                'method' => $req->method,
                'scheme' => $uri->scheme,
                'host'   => $uri->host,
                'url'    => $uri->path,
                %{ $req->headers }
                );
        $headers{'version'} ||= 'HTTP/1.1';

        if(defined $req->content) {
            $headers{'content'} = $req->content;
        }
    }
    else {
        unshift @_, $req;
        %headers = @_;
    }

    my @unex_required = grep { not exists $headers{$_} }
    ('method', 'scheme', 'url', 'version');
    warn "Unexisted required field: $_\n" for @unex_required;
    return undef if @unex_required;

    if(exists $headers{'content'}) {
        $content = $headers{'content'};
        delete $headers{'content'};
    }

    my %frame = (
            'type'      => SYN_STREAM,
            'stream_id' => $self->{'stream_no'},
            'assoc_to'  => 0,
            'pri'       => 0,
            'headers'   => \%headers,
            'flags'     => FLAG_FIN,
            );

    $self->{'stream_no'} += 2;

    if($headers{'method'} eq 'POST') {
        $frame{'content-length'} = length $content;
    }

    if($content) {
        $frame{'flags'} = 0;
    }

    $frame = $self->{'protocol'}->pack_frame(%frame);
#        print "Stream $frame{'stream_id'} started\n"; #DEBUG
    $self->_send($frame);

    if($content) {
        $self->_send_data($content, $frame{'stream_id'});
    }

    return $frame{'stream_id'};
}

sub is_ready {
    my ($self, $no) = @_;
    return defined $self->{'repls'}->[$no] &&
        $self->{'repls'}->[$no]->content ? 1 : 0
}

sub get {
    my ($self, $no) = @_;
    return $self->{'repls'}->[$no];
}

sub _connect {
    my $self = shift;
    my $serv_iaddr = inet_aton($self->{'host'}) or return undef;
    my $serv_addr  = sockaddr_in($self->{'port'}, $serv_iaddr) or return undef;

    socket ($self->{'socket'}, PF_INET, SOCK_STREAM, getprotobyname 'tcp') or return undef;
    connect ($self->{'socket'}, $serv_addr) or return undef;
    select  ($self->{'socket'});
    $| = 1;
    select (STDOUT);

    if($self->{'scheme'} eq 'https') {
        require Net::SSLeay;

        Net::SSLeay::load_error_strings();
        Net::SSLeay::SSLeay_add_ssl_algorithms();
        Net::SSLeay::randomize();

        $self->{'ctx'} = Net::SSLeay::new_x_ctx();
        if (Net::SSLeay::print_errs('CTX_new') or !$self->{'ctx'}) {
            $self->close();
            return undef;
        }

        Net::SSLeay::CTX_set_options($self->{'ctx'}, Net::SSLeay::OP_ALL());
        if (Net::SSLeay::print_errs('CTX_set_options')) {
            $self->close();
            return undef;
        }

        Net::SSLeay::CTX_set_next_proto("spdy/2");
        Net::SSLeay::CTX_set_next_proto_select_cb($self->{'ctx'});

        $self->{'ssl'} = Net::SSLeay::new($self->{'ctx'});
        if (Net::SSLeay::print_errs('SSL_new') or !$self->{'ssl'}) {
            $self->close();
            return undef;
        }

        Net::SSLeay::set_fd($self->{'ssl'}, fileno($self->{'socket'}));
        if (Net::SSLeay::print_errs('set_fd')) {
            $self->close();
            return undef;
        }

        Net::SSLeay::connect($self->{'ssl'});
        if(Net::SSLeay::print_errs('SSL_connect')) {
            $self->close();
            return undef;
        }
    }

    my $flags = fcntl($self->{'socket'}, F_GETFL, 0);
    fcntl($self->{'socket'}, F_SETFL, $flags | O_NONBLOCK);
    return 1;
}

sub _send_data {
    my ($self, $data, $stream_id) = @_;
    my @chunks = unpack 'a' . DATA_SIZE . '*', $data;

    for my $i (0 .. $#chunks) {
        my $frame = $self->{'protocol'}->pack_frame({
                'type'      => DATA,
                'stream_id' => $stream_id,
                'flags'     => $i == $#chunks ? FLAG_FIN : 0,
                'data'      => $chunks[$i]
                });
        $self->_send($frame);
    }
}

sub _send {
    my ($self, $data) = @_;

    if($self->{'scheme'} eq 'https') {
        my ($written, $errs) = Net::SSLeay::ssl_write_all($self->{'ssl'}, $data);
#            print "written $written need:" . length ($data) . "\n"; #DEBUG
    }
    else {
        syswrite $self->{'socket'}, $data;
    }
}

sub _recv {
    my $self = shift;

    vec(my $vec = '', fileno ($self->{'socket'}), 1) = 1;
    while (select($vec, undef, undef, undef)) {
        my $got = Net::SSLeay::read($self->{'ssl'});
#            print "Got: " . length ($got) . "\n" if $got; #DEBUG
        sleep 0.1 if not $got;
        last if Net::SSLeay::print_errs('SSL_read');
        my @repls = $self->{'protocol'}->parse($got);
        $self->_process(@repls) if @repls;
    }
}

sub _process {
    my ($self, @frames) = @_;
    my ($headers, $content, $code, $mes);

    for my $frame (@frames) {
#            print "Got frame $frame->{'type'}\n"; #DEBUG
#            print "Processing $frame->{'stream_id'} stream\n" if $frame->{stream_id};#DEBUG
        if ($frame->{'type'} == SYN_REPLY) {
            my $hdrs = $frame->{'headers'};
            ($code, $mes) = $hdrs->{'status'} =~ /(\d+) (.*)/;
            delete $hdrs->{'status'};
            $headers = HTTP::Headers->new(%$hdrs);
            $self->{'repls'}->[$frame->{'stream_id'}] =
                shared_clone (HTTP::Response->new($code, $mes, $headers, ''));
        }
        if ($frame->{'type'} == DATA) {
            $self->{'stream_data'}->[$frame->{'stream_id'}] .= $frame->{'data'};

        }
        if($frame->{'flags'} & FLAG_FIN) {
#                print "Stream $frame->{'stream_id'} complete.\n"; #DEBUG
            $content = $self->{'stream_data'}->[$frame->{'stream_id'}];
            $self->{'repls'}->[$frame->{'stream_id'}]->content($content);
        }
    }
}

sub close {
    my $self = shift;

    if($self->{'scheme'} eq 'https') {
        Net::SSLeay::free ($self->{'ssl'}) if defined $self->{'ssl'};
        Net::SSLeay::print_errs('SSL_free');
        Net::SSLeay::CTX_free ($self->{'ctx'}) if defined $self->{'ctx'};
        Net::SSLeay::print_errs('CTX_free');
    }

    close $self->{'socket'};
}
1;
__END__

=head1 NAME

SPDY::Client - Perl Client for SPDY - protocol

=head1 SYNOPSIS

    use SPDY::Client;
    use Time::HiRes qw(sleep);

    my %headers = (
            'host'    => 'encrypted.google.com',
            'method'  => 'GET',
            'scheme'  => 'https',
            'url'     => '/',
            'version' => 'HTTP/1.1'
     );

    my $client = SPDY::Client->new('encrypted.google.com', 'https');
    my $ticket = $client->add_stream(%headers);
    sleep 0.1 while not $client->is_ready($ticket);
    my $resp =  $client->get($ticket);
    if($resp->is_success) {
        print $resp->decoded_content();
    }
    else {
        print STDERR $response->status_line, "\n";
    }
    $client->close;

=head1 DESCRIPTION


Simple client for testing experimental SPDY protocol. Client can asynchronously process HTTP queries and return results.

Functions:

    SPDY::Client->new($domain, $protocol, [$port]);
Creates new client and connects to $domain on $port using $protocol. Protocol must be http or https.

    $client->add_stream($request);
Adds stream specified by hashmap of headers of HTTP::Request object. Returns a ticket number.

    $client->is_ready($ticket);
Checks is request $ticket ready. Returns 1 un success or 0 on fail.

    $client->get($ticket);
Returns HTTP::Response object if request is ready, undef otherwise.

=head1 SEE ALSO

SPDY protocol - E<lt>http://www.chromium.org/spdyE<gt>

=head1 AUTHOR

Yegor Kolmogortsev, E<lt>eburgforever@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Yegor Kolmogortsev

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
