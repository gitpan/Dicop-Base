#############################################################################
# Dicop::Config -- manage config files
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Config;
use vars qw($VERSION);
$VERSION = 1.02;	# Current version of this package
require  5.004;		# requires this Perl version or later

use strict;

use Dicop::Event qw/crumble msg/;

sub new
  {
  # create a new config, parameters:
  #  * file to read in
  #  * ALLOWED_KEYS, a hash mapping { key => type }
  my $class = shift;
  $class = ref($class) || $class || __PACKAGE__;
  
  my $self = {}; bless $self, $class;

  $self->{_file} = shift;
  $self->{_lines} = {};
  $self->{_ALLOWED_KEYS} = shift;
  $self->{_modified} = 0;
  $self->_read($self->{_file});
  $self;
  }
 
sub set
  {
  # set a config value
  my $self = shift;
  
  my $args = {};
  ref $_[0] ? $args = shift : $args = { @_ };

  foreach (keys %$args)
    {
    crumble ("Can't set private config variable '$_'") if /^_/;
    $self->{$_} = $args->{$_};
    }
  $self->{_modified} = 1;
  $self;
  }

sub get
  {
  # get a config value
  my $self = shift;
  
  my $key = shift;

  return unless exists $self->{$key};
  $self->{$key};
  }

sub _read
  {
  # read config data
  my ($self,$file) = @_;

  my ($var,$val);
  open (SOMEFILE, $file) or die crumble("Can't read $file: $!");
  $/ = "\n";		# v5.6.0 seems to destroy this sometimes
  my $line_nr = -1;
  while (<SOMEFILE>)
    {
    $line_nr++;
    next if /^\s*$/;
    next if /^\s*#/;
    if ($_ =~ /\s*([A-Za-z0-9_]+)\s*=\s*"?([^"\n]*)"?\s*$/)
      {
      $var = lc($1); $val = $2;
      $self->{_lines}->{$var} = $line_nr;
      if (exists $self->{$var})
        {
        $self->{$var} = [ $self->{$var} ] unless ref $self->{$var};
        push @{$self->{$var}},$val;
        }
      else
        {
        $self->{$var} = $val;
        }
      }
    }
  close (SOMEFILE);
  $self;
  }

sub _write
  {
  # write config data
  my $self = shift;

  # XXX TODO

  $self;
  }

sub flush
  {
  # write config data back if modified
  my $self = shift;

  return unless $self->{_modified};
  $self->_write();
  }

sub check
  {
  # Check all keys in the config for being valid. Optional param is allowed
  # keys as hash ref.
  # return undef for ok, or error code and message
  my ($self,$allowed) = @_;
  
  $self->{_ALLOWED_KEYS} = $allowed if defined $allowed;
  my $lines = $self->{_lines} || {};

  foreach my $key (keys %$self)
    {
    next if $key =~ /^_/;		# skip internals

    my $msg = $self->_check_entry($key,$lines->{$key});
    return $msg if defined $msg;
    }
  undef;
  }

sub _check_entry
  {
  # check one key and its value for being valid
  # return undef for ok, or error code and message
  my ($self,$key,$line) = @_;

  # not existing => invalid key
  return msg (801,$key,$self->{_file},$line || 0) unless exists $self->{_ALLOWED_KEYS}->{$key};

  # not defined => obsolete key
  return msg (804,$key,$self->{_file},$line || 0) unless defined $self->{_ALLOWED_KEYS}->{$key};
  undef;
  }

sub type
  {
  # return the type of a config key or undef
  my ($self,$key) = @_;

  return unless exists $self->{_ALLOWED_KEYS}->{$key};
  $self->{_ALLOWED_KEYS}->{$key};
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Config -- manage config files

=head1 SYNOPSIS

	use Dicop::Config;

	my $config = new Dicop::Config ('data/server.cfg');
	print $config->{logging_dir},"\n";

=head1 REQUIRES

perl5.004, Exporter

=head1 EXPORTS

Exports nothing.

=head1 DESCRIPTION

This module reads config files and stores their contents in memory.

=head1 METHODS

=head2 new()

Create a new config object from a file. The only parameter is the file
name to read in.

=head2 _read()

Read in the config. Called automatically by L<new()>.

=head2 _write()

Write the config back to disk. Not implemented yet. Use C<flush()>.

=head2 flush()

If config was modified, write it back to disk. Does call L<_write()> and thus
not work yet.

=head2 set()

C<set()> one or more config value(s):

	$config->set( logging_dir => 'logs', blah => 9, );
	$config->set( { foo => 9 });
	$config->flush();			# write back

This automatically tags the config data as modified, so that the next L<flush()>
writes it out.	

=head2 get()

	$config->get('field');

Return the value of the config entry named C<field>.

=head2 check()

        my $msg = $config->check();

        $msg = $config->check( { name => $line_nr1, foo => undef, } );

Check the config for being ok. Returns undef for ok, otherwise
the error message.

The optional parameter is a hash, listing the allowed/obsolete keys. Allowed
ones map the key name to the key type. If the type is undef, the key is
obsolete and should not be in the config file.

=head2 _check_entry()

        my $msg = $config->_check_entry( $key );

Internally used by C<check()>.

Check one config entry consisting of the key and its value.
Returns undef for ok, otherwise the error message.

C<$config_file> is an optional config file name for the potentially returned
error message. C<$line_numbers> is a hash containing as keys the read in
keys of the config, and as values the line from which this key was read. This
is also used for the potential error message.

=head2 type()

        $type = $config->type($key);

Return the type of a config key. Returns undef for invalid keys.

=head1 BUGS

=over 2

=item *

_write() is not implemented yet, thus flush() does nothing at the moment.

=back

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

