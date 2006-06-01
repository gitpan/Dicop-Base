#############################################################################
# Dicop::Client::wget -- connect to server via wget
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Client::wget;
use vars qw($VERSION);
$VERSION = '1.05';	# Current version of this package
require  5.008001;	# requires this Perl version or later

use strict;
use Dicop::Event qw/crumble msg logger load_messages/;
use Dicop::Base qw/read_file/;

sub new
  {
  # create a new user-agent object
  my $class = shift;
  $class = ref($class) || $class || 'Dicop::Client::wget';
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

  $self->{ua} = $args->{useragent} || "DiCoP Client/$VERSION (wget)";
  $self->{proxy} = lc($args->{proxy} || "on");
  $self->{code} = 500;		# first access to is_succes is false
  $self->{content} = '';
  
  return $self;
  }

sub agent
  {
  # set/get the user agent string
  my $self = shift;

  if (defined $_[0])
    {
    $self->{ua} = shift || "DiCoP Client/$VERSION (wget)";
    }
  $self->{ua};
  }

sub is_success
  {
  my $self = shift;

  return 1 if $self->{code} >= 200 && $self->{code} < 300;
  0;
  }

sub code
  {
  my $self = shift;

  $self->{code};
  }

sub content
  {
  my $self = shift;

  ${$self->{content}};
  }

sub post
  {
  # submit a form via PUT method
  my ($self,$server,$params) = @_;
 
  return $self->get("$server?$params");
  }

sub get
  {
  # retrieve an URL via GET
  my ($self,$url) = @_;

  my $tmp = 'cache/response.txt';
  my $head = 'cache/header.txt';

  unlink $tmp if -e $tmp;
  die ("Cannot unlink '$tmp': $!") if -e $tmp;
  unlink $head if -e $head;
  die ("Cannot unlink '$head': $!") if -e $head;

  my $cmdline = 
   "wget -S -Y $self->{proxy} -U \"$self->{ua}\" -O $tmp \"$url\" 2>$head";
  $self->{result} = `$cmdline`;
  # read in the actual response
  $self->{content} = read_file($tmp,1);
  my $rc = read_file($head);

  if (ref($rc))
    {
    $self->{code} = 500;		# some error occured
    return $self;
    }

  #unlink $tmp;
  #unlink $head;

  $$rc =~ /[0-9]{1,2}\s+HTTP\/1\.[01]\s([0-9]{3})\s/;
  if (!defined $1)
    {
    # another output style of wget's header information
    $$rc =~ /awaiting response\.+\s(\d+)\s/;
    $self->{code} = $1 || 500;		# extract return code
    }
  else
    {
    $self->{code} = $1 || 500;		# extract return code
    }
  $self;				# return self as faked response object
  }

sub message
  {
  my $self = shift;

  "$self->{code} $self->{result}";
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Client::wget -- a connector object for Dicop::Client using wget

=head1 SYNOPSIS

	use Dicop::Client::wget;
	use Dicop::Client;

	my $ua = Dicop::Client::wget->new();
	my $client = Dicop::Client->new ( ua => $ua );
        $client->work();		# never returns

=head1 REQUIRES

perl5.008001, wget

=head1 DESCRIPTION

This module represents a connector object for the client and manages the
actual connection between server and client. It uses the popular C<wget>
program to do the work.

=head1 METHODS

=head2 new()

Create a new object.

=head2 agent()

Set/get the user agent string.

	my $agent = $ua->agent();
	$ua->agent('UserAgent/1.0');
  
=head2 post()

Given a server url and a parameter string, simulates a PUT request:

	$response = $ua->put('http://127.0.0.1:8888/',$params);

=head2 get()

Given a server url and a parameter string, simulates a GET request:
	
	$response = $ua->get('http://127.0.0.1:8888/files/main');

=head2 message()

	$msg = $ua->message();

If the connect failed, this method returns a human-readable error message.

=head2 code()

Return the HTTP respone code from the server for the last post() or get().

=head2 is_success()

Return true if the last request from the server did not result in an error.

=head2 content()

	my $content = $ua->content();

Return the content of the last successfull post() or get() call.

=head1 BUGS

None discovered yet.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

