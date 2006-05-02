#############################################################################
# Dicop::Connect -- connect upstream server via LWP or WGET
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Item;
use vars qw/$VERSION $BUILD @ISA @EXPORT_OK/;

use strict;
use Dicop::Event qw/crumble msg/;

require Exporter;
@ISA = qw/Exporter/;

@EXPORT_OK = qw/_connect_server _load_connector/;

# Load these connector modules on compile-time, because otherwise their
# loading at runtime via require would fail under chroot() environments:
use Dicop::Client::wget;
use Dicop::Client::LWP;

sub _connect_server
  {
  # take params or URL and send them via LWP/WGET to the server
  # used by proxy, client and server all alike
  my ($self,$url,$params,$max_tries,$noretry) = @_;

  #         Client       or Proxy/Server
  my $cfg = $self->{cfg} || $self->{config};

  my $retries = 0;
  $max_tries = 16 if ($max_tries || 0) == 0;
  my ($req,$res);
  RETRY:
  while ($retries++ < $max_tries)
    {
    # find us a server if no url/server was specified
    if (!defined $url)
      {
      my $server = $cfg->{server};
      if (ref($server) eq 'ARRAY')
        {
        my $r = 0;
        $r = rand(scalar @$server) if ($cfg->{random_server} || 0);
        $server = $server->[$r];
        }
      $server = $server . '/' unless $server =~ /\/$/;
      $self->output ("Will send to server:\n'$params'\n") if $self->{debug} > 0;
      $self->output (scalar localtime," Contacting $server...");
      $res = $self->{ua}->post($server,$params);
      }
    else
      {
      $self->output ("Retrieving $url...");
      $res = $self->{ua}->get($url);
      }

    if ($res->is_success())
      {
      $self->output ("ok.\n"); last RETRY;
      }
    $self->output ("failed.\n");
    if (defined $noretry)
      {
      # for downloading, no retry nor sleep
      $self->output ("Error " . $res->code() . " " . $res->message()."\n");
      return $res;
      }
    $self->_sleeping($res->code(),$res->message()."\n");
    }
  $self->_die_hard ("Failed too many times. I give up.\n") if $retries >= $max_tries;
  $res;
  }

sub _load_connector
  {
  # load a connector module (LWP, wget etc) and construct a user-agent object for it
  my ($self,$cfg,$args) = @_;

  my $via = $cfg->{via} || $args->{via} || 'LWP';
  # split up eventual parameters for the via argument
  my @params;
  ($self->{via},@params) = split (/,/, $via);

  $self->{via} = "Dicop::Client::$self->{via}";

  # load the connector module (that is not very portable)
  my $s = $self->{via}; $s =~ s/::/\//g; $s .= '.pm';

  if (!require $s)
    {
    require Carp;
    Carp::Confess("$self couldn't load $s: $!");
    }

  # add the parameters from the via argument, convert "proxy=OFF,foo=bar" to hash
  my $par = {};
  foreach my $p (@params)
    {
    my ($var,$val) = split (/=/,$p);
    $par->{$var} = $val;
    }
  # create the connector object
  $self->{ua} = $self->{via}->new( $par );

  if (! ref $self->{ua})
    {
    require Carp;
    Carp::confess ("$self needs a user-agent object"); 
    }

  # set the user agent string from via and our VERSION
  $via = lc($self->{via}); $via =~ s/.*:://;
  my $type = ref($self); $type =~ s/^Dicop:://;

  no strict 'refs';
  my $ver = ${ref($self).'::VERSION'} || 'unknown';
  my $build = ${ref($self).'::BUILD'} || 'unknown';
  
  $self->{ua}->agent("DiCoP $type/$ver build $build ($via)");

  $self;
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Connect - connect upstream server via LWP or WGET

=head1 SYNOPSIS

	use Dicop::Connect qw/_connect_server/;

	$self->_connect_server ($url, undef );

=head1 REQUIRES

Exporter, Dicop::Event

=head1 EXPORTS

Can export on request:

	_connect_server()
	_load_connector()

=head1 DESCRIPTION

Dicop::Connect provides a method for connecting other servers (HTTP, FTP etc)
and fetching URLs from them, or sending them FORM requests via HTTP POST.

=head1 METHODS

=head2 _connect_server

Make one connection to a server and send requests to it. Retry multiple times
in case of error. Return result of connect.

        my $result = $self->_connect_server ($url,$params,$max_tries);

Returns an object which can be queried for is_sucess(), code() and contents().

C<$max_tries> defaults to 20. if C<$url> is undefined, the predefined (config)
server or an random server will be used, otherwise the URL must contain
protocoll, hostname etc:

        my $result = $self->_connect_server(undef,$params);      # main server
        my $result = $self->_connect_server(
          'http://localhost:8000/files/worker/linux/test/');    # file server

=head2 _load_connector

	$self->_load_connector($config, $arguments);

This routine loads a connector module (specified in config or arguments
as key 'via'), then constructs a user-agent object and sets the proper
user agent string in it. The user agent will be used via $self->{ua}
later on in L<_connect_server()>.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

