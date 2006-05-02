#############################################################################
# Dicop::Client::LWP -- connect to server via libwww
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Client::LWP;
use vars qw($VERSION);
$VERSION = '1.02';	# Current version of this package
require  5.004;		# requires this Perl version or later

require Exporter;
@ISA = qw/Exporter/;
use strict;

use Dicop::Event qw/crumble msg logger load_messages/;
use LWP::UserAgent;

# preload these for chroot environments (need others?)
use LWP::Protocol::ftp;
use URI::ftp;
use LWP::Protocol::http;
use URI::http;
use HTML::HeadParser;
use HTTP::Message;
use HTTP::Response;
use HTTP::Request;

sub new
  {
  # create a new user-agent object
  my $class = shift;
  $class = ref($class) || $class || 'Dicop::Client::LWP';
  my $self = {};
  bless $self, $class;
  $self->_init(@_);
  return $self;
  }

sub _init
  {
  # read in config, set up data
  my $self = shift;
  my $args = $_[0] || {};
  $args = { @_ } if @_ > 0 && ref $args ne 'HASH';

  $self->{ua} = LWP::UserAgent->new();
  $self->{ua}->agent ( $args->{useragent} || "DiCoP Client/$VERSION (libwww)" );
  
  $self;
  }

sub agent
  {
  # set/get the user agent string
  my $self = shift;

  if (defined $_[0])
    {
    $self->{ua}->agent(shift);
    }
  $self->{ua}->agent();
  }

sub post
  {
  # submit a form via PUT method
  my ($self,$server,$params) = @_;
  
  my $req = HTTP::Request->new( POST => $server );
  $req->content_type('application/x-www-form-urlencoded');
  $req->content($params);
  
  $self->{ua}->request($req);  	# make contact and return response
  }

sub get
  {
  # retrieve an URL via GET
  my ($self,$url) = @_;

  my $req = HTTP::Request->new( GET => $url );
  $self->{ua}->request($req);  	# make contact and return response
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Client::LWP - a connector object for Dicop::Client using libwww

=head1 SYNOPSIS

	use Dicop::Client;

	my $client = Dicop::Client->new ( via => 'LWP' );
        $client->work();		# never returns

=head1 REQUIRES

perl5.004, Exporter

=head1 EXPORTS

Exports nothing per default.

=head1 DESCRIPTION

This module represents a connector object for the client/proxy and manages the
actual connection from the client/proxy to the server.

=head1 METHODS

=head2 new

Create a new object.

=head2 agent

Set/get the user agent string.

	my $agent = $ua->agent();
	$ua->agent('UserAgent/1.0');
  
=head2 post

Given a server url and a parameter string, simulates a PUT request:

	$response = $ua->put('http://127.0.0.1:8888/',$params);

=head2 get

Given a server url and a parameter string, simulates a GET request:
	
	$response = $ua->get('http://127.0.0.1:8888/files/main');

=head1 BUGS

=over 2

=item *

Under a chroot environment, loading LWP will fail because it might
not be able to load all the neccessary data (like /etc/protocols),
and errors like C<Bad protocol 'tcp'> or C<Cannot locate URI/_foreign>
might appear.

=back

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

