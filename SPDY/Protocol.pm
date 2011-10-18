#!/usr/bin/perl

package SPDYv2Protocol;
    use strict;
    use warnings;

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
