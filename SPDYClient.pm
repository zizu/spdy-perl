#!/usr/bin/perl

package SPDYConnection;
    use Socket;
    use URI;
    use HTTP::Response;
    use HTTP::Headers;
    use Time::HiRes qw(sleep);
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
        threads->create('SPDYConnection::_recv', $self)->detach;

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

package SPDYv2Protocol;
    use Compress::Zlib;
    use constant {
        INT_31_MASK => 0x7FFFFFFF,
        INT_24_MASK => 0xFFFFFF,
        INT_15_MASK => 0x7FFF,

        SPDY_2_HEADER_MASK => 'B@0(a4)@4C@4N',
        SPDY_2_HEADER_SIZE => 8,

        CONTROL_HEADER_MASK => 'nnC(a3)(a*)',
        DATA_HEADER_MASK    => 'NC(a3)(a*)',

        SPDY_VERSION => 2,

        ZLIB_DICT => "optionsgetheadpostputdeletetraceacceptaccept-charsetacc" .
                     "ept-encodingaccept-languageauthorizationexpectfromhosti" .
                     "f-modified-sinceif-matchif-none-matchif-rangeif-unmodif" .
                     "iedsincemax-forwardsproxy-authorizationrangerefererteus" .
                     "er-agent10010120020120220320420520630030130230330430530" .
                     "6307400401402403404405406407408409410411412413414415416" .
                     "417500501502503504505accept-rangesageetaglocationproxy-" .
                     "authenticatepublicretry-afterservervarywarningwww-authe" .
                     "nticateallowcontent-basecontent-encodingcache-controlco" .
                     "nnectiondatetrailertransfer-encodingupgradeviawarningco" .
                     "ntent-languagecontent-lengthcontent-locationcontent-md5" .
                     "content-rangecontent-typeetagexpireslast-modifiedset-co" .
                     "okieMondayTuesdayWednesdayThursdayFridaySaturdaySundayJ" .
                     "anFebMarAprMayJunJulAugSepOctNovDecchunkedtext/htmlimag" .
                     "e/pngimage/jpgimage/gifapplication/xmlapplication/xhtml" .
                     "text/plainpublicmax-agecharset=iso-8859-1utf-8gzipdefla" .
                     "teHTTP/1.1statusversionurl\x00",

        NAME_VALUE_UNPACK => 'n/(n/an/a)',
        NAME_VALUE_PACK   => 'n(n/an/a)*',

        SYN_STREAM_MASK => 'NNn(a*)',
        SYN_REPLY_MASK  => 'Nx[n](a*)',
        RST_STREAM_MASK => 'NN',
        SETTINGS_MASK   => 'N/((a3)CN)',
        PING_MASK       => 'N',
        GOAWAY_MASK     => 'N',
        HEADERS_MASK    => 'Nx[n](a*)',
    };

    sub new {
        my $class = shift;
        my $version = shift || 2;

        my $self = bless({}, $class);
        $self->{'buffer'}   = '';
        $self->{'version'}  = $version;
        $self->{'inflater'} = inflateInit(-Dictionary => ZLIB_DICT);
        $self->{'deflater'} = deflateInit(-Dictionary => ZLIB_DICT);
        $self->{'packers'}  = [
#0 
            sub { },
#1 SYN_STREAM
            sub {
                my ($self, %frame) = @_;
                return pack SYN_STREAM_MASK,
                    $frame{'stream_id'}, $frame{'assoc_to'},
                    $frame{'pri'} << 14, $self->_pack_name_value(%{ $frame{'headers'} });
            },
#2 SYN_REPLY
            sub {
                my ($self, %frame) = @_;
                return pack SYN_REPLY_MASK, $frame{'stream_id'} ,
                    $self->_pack_name_value(%{ $frame{'headers'} });
            },
#3 RST_STREAM
            sub {
                my ($self, %frame) = @_;
                return pack RST_STREAM_MASK, $frame{'stream_id'}, $frame{'status_code'};
            },
#4 SETTINGS
            sub {
                my ($self, %frame) = @_;
                return pack SETTINGS_MASK, map {
                    _pack_int_24_le(${ $frame{$_} }[0]),
                    $_, ${ $frame{$_} }[1]
                } grep {/^\d+$/} sort keys %frame;
            },
#5 NOOP
            sub { return '' },
#6 PING
            sub {
                my ($self, %frame) = @_;
                return pack PING_MASK, $frame{'id'};
            },
#7 GOAWAY
            sub {
                my ($self, %frame) = @_;
                return pack GOAWAY_MASK, $frame{'id'};
            },
#8 HEADERS
            sub {
                my ($self, %frame) = @_;
                return pack HEADERS_MASK, $frame{'id'}, 
                    $self->_pack_name_value(%{ $frame{'headers'}});
            }
        ];

        $self->{'unpackers'} = [
#0 Wrong mes.
            sub { warn "Wrong mes no: 0"; },
#1 SYN_STREAM
            sub {
                my ($self, $packed) = @_;
                my (%frame, $headers);

                ($frame{'stream_id'}, $frame{'assoc_to'}, $frame{'pri'},
                    $headers) = unpack SYN_STREAM_MASK, $packed;
                $frame{'stream_id'} &= INT_31_MASK;
                $frame{'assoc_to'}  &= INT_31_MASK;
                $frame{'pri'} >>= 14;
                my $inflated = $self->{'inflater'}->inflate(\$headers);
                $frame{'headers'} = { unpack NAME_VALUE_UNPACK, $inflated };

                return %frame;
            },
#2 SYN_REPLY
            sub {
                my ($self, $packed) = @_;
                my (%frame, $headers);

                ($frame{'stream_id'}, $headers) = unpack SYN_REPLY_MASK, $packed;
                $frame{'stream_id'} &= INT_31_MASK;

                my $inflated = $self->{'inflater'}->inflate(\$headers);
                $frame{'headers'} = { unpack "n/(n/an/a)", $inflated };

                return %frame;
            },
#3 RST_STREAM
            sub {
                my ($self, $packed) = @_;
                my %frame;

                ($frame{'stream_id'}, $frame{'status_code'})
                    = unpack RST_STREAM_MASK, $packed;
                $frame{'stream_id'} &= INT_31_MASK;

                return %frame;
            },
#4 SETTINGS
            sub {
                my ($self, $packed) = @_;
                my %frame;
                my @tmp = unpack SETTINGS_MASK, $packed;

                for(my $i = 0; $i < @tmp; $i += 3) {
                    my $id = _unpack_int_24_le($tmp[$i]);
                    my $flags = $tmp[$i + 1];
                    my $value = $tmp[$i + 2];
                    $frame{$id} = [$flags, $value];
                }

                return %frame;
            },
#5 NOOP
            sub { return () },
#6 PING
            sub {
                my ($self, $packed) = @_;
                my %frame;

                $frame{'id'} = unpack PING_MASK, $packed;
                $frame{'id'} &= INT_31_MASK;

                return %frame;
            },
#7 GOAWAY
            sub {
                my ($self, $packed) = @_;
                my %frame;

                $frame{'id'} = unpack GOAWAY_MASK, $packed;
                $frame{'id'} &= INT_31_MASK;

                return %frame;
            },
#8 HEADERS
            sub {
                my ($self, $packed) = @_;
                my (%frame, $headers);

                ($frame{'id'}, $headers) = unpack HEADERS_MASK, $packed;
                $frame{'id'} &= INT_31_MASK;
                my $inflated = $self->{'inflater'}->inflate(\$headers);
                $frame{'headers'} = { unpack NAME_VALUE_UNPACK, $inflated };

                return %frame;
            }
        ];

        return $self;
    }

    sub parse {
        my ($self, $unparsed) = @_;
        my @frames;
        return if not $unparsed;
        $self->{'buffer'} .= $unparsed;
#        print "Parse was called, buffer: " . length ($self->{'buffer'}) . "\n"; #DEBUG
        while(length $self->{'buffer'} > SPDY_2_HEADER_SIZE) {
            my ($is_control, $tmp, $flags, $length) =
                unpack(SPDY_2_HEADER_MASK, $self->{'buffer'});
            $length &= INT_24_MASK;

            last if length $self->{'buffer'} < $length + SPDY_2_HEADER_SIZE;

            my $data = substr($self->{'buffer'}, SPDY_2_HEADER_SIZE, $length);
            $self->{'buffer'} = substr($self->{'buffer'}, $length + SPDY_2_HEADER_SIZE);

            if($is_control) {
                my ($version, $type) = unpack("nn", $tmp);
                $version &= INT_15_MASK;
                push @frames, {
                    'type'  => $type,
                    'flags' => $flags,
                    &{ ${ $self->{'unpackers'} }[$type] }($self, $data)
                };
            }
            else {
                my $stream_id = unpack ("N", $tmp) & INT_31_MASK;
                push @frames, {
                    'type'      => 0,
                    'flags'     => $flags,
                    'data'      => $data,
                    'stream_id' => $stream_id,
                };
            }
        }
        return @frames;
    }

    sub pack_frame {
        my ($self, %frame) = @_;
        my $type = $frame{'type'};

        if($type != 0) { #control frame
            my $data = &{ ${ $self->{'packers'} }[$type] }($self, %frame);
            my $packed = pack CONTROL_HEADER_MASK,
                            $self->{'version'}, $type, $frame{'flags'},
                            _pack_int_24_be(length $data), $data;
            vec($packed, 7, 1) = 1; #set control bit
            return $packed;
        }
        else { #data frame
            my $packed = pack DATA_HEADER_MASK,
                            $frame{'stream_id'}, $frame{'flags'},
                            _pack_int_24_be(length $frame{'data'}),
                            $frame{'data'};
            vec($packed, 7, 1) = 0; #unset control bit
            return $packed;
        }
    }

    sub _pack_name_value {
        my ($self, %name_value) = @_;

        return $self->{'deflater'}->deflate(
                   pack NAME_VALUE_PACK,
                   scalar keys %name_value,
                   map {$_, $name_value{$_} } sort keys %name_value
               ) . $self->{'deflater'}->flush(Z_SYNC_FLUSH);
    }

#pack to big endian 24 bit unsigned int
    sub _pack_int_24_be {
        return unpack 'x[a](a3)', pack 'N', shift;
    }

#unpack from big endian 24 bit unsigned int
    sub _unpack_int_24_be {
        return unpack 'N', "\x00" . shift;
    }

    sub _pack_int_24_le {
        return unpack '(a3)', pack 'L', shift;
    }

    sub _unpack_int_24_le {
        return unpack 'L', shift() . "\x00";
    }
1;
