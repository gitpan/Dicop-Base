#############################################################################
# Dicop::Hash - manage hashes (MD5 etc) for files
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2008
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Hash;
$VERSION = 1.06;	# Current version of this package
require  5.004;		# requires this Perl version or later

use strict;

use Dicop::Event qw/crumble/;
use Digest::MD5;

sub new
  {
  # create a new hash, parameter is file to read in (or ref to scalar to hash)
  my $class = shift;
  $class = ref($class) || $class || __PACKAGE__;
  my $self = {};
  bless $self, $class;
  $self->{_hash} = '';
  $self->{_error} = '';
  $self->{_modified} = time;
  $self->{_size} = 0;
  $self->read(@_);
  $self;
  }
 
sub read
  {
  # read file, hash it and store hash value
  my ($self,$file) = @_;

  $self->{_hash} = '';

  $self->{_error} = '';				# reset error
  my $md5 = Digest::MD5->new();
  if (ref($file))
    {
    $self->{_file} = \'SCALAR';			# for update()
    $self->{_size} = length($$file);
    $md5->add($$file);
    }
  else
    {
    $self->{_file} = $file;
    $self->{_error} = "Cannot hash '$file': $!" and return
      unless -f $self->{_file};			# no regular file?

    my @stat = stat($self->{_file});
    $self->{_size} = $stat[7];			# store size
    $self->{_modified} = $stat[9];		# store mtime

    open (SOMEFILE, $file) or (($self->{_error} = $!) and return);
    binmode SOMEFILE;				# for non-unix
    $md5->addfile(*SOMEFILE);
    close (SOMEFILE) or ($self->{_error} = "Cannot close '$file': $!");
    }

  $self->{_hash} = $md5->hexdigest();
  
  $self;
  }

sub as_hex
  {
  my $self = shift;
  $self->update();

  return \"$self->{_error}" if $self->{_error};
  return \"Unknown error - hash is empty" if $self->{_hash} eq '';
  $self->{_hash};
  }

sub error
  {
  my $self = shift;

  $self->{_error};
  }

sub update
  {
  my $self = shift;

  return $self if ref($self->{_file});					# in memory file

  $self->{_error} = "Cannot hash '$self->{_file}': $!" and return $self
    unless -f $self->{_file};	# file does not exist?

  my @stat = stat($self->{_file});

  if ( $self->{_error} ||  				# in case of error, try again
	($stat[9] != $self->{_modified}) ||		# or if file modified
	($stat[7] != $self->{_size}))			# or if size changed
    {
    $self->read($self->{_file});			# rehash
    }
  $self;
  }

sub compare
  {
  my ($self,$other) = @_;

  # as_hex() calls update() for us
  # XXX TODO: md5=1234 vs. 1234
  $self->as_hex() eq $other->as_hex();
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Hash -- manage hashes over files

=head1 SYNOPSIS

	use Dicop::Hash;

	my $hash = Dicop::Hash->new('worker/linux/test');
	$hash->update();	# to see whether file has changed
	print $hash->as_hex();

	my $hash2 = Dicop::Hash->new(\'Some static text');
	$hash2->update();	# no-op
	print $hash2->as_hex();

	print $hash->compare($hash2) ? 'equal' : 'not equal';

=head1 REQUIRES

perl5.005, Exporter

=head1 EXPORTS

Exports nothing per default.

=head1 DESCRIPTION

This module manages all the file hashes for the server. It currently uses MD5
as hashing algorithmn.

=head1 METHODS

=head2 new

Create a new hash object. The only parameter is a filename to read in and
calculate the hash over, or alternatively a ref to a scalar to hash.

=head2 read

Read in a file and then hash the file data, store hash along with time stamp.

=head2 update

When the file has changed, recalculate hash. Otherwise do nothing. Called by
C<as_hex()> automatically.

=head2 as_hex

Return hash value as hexified string. Does update the hash value if neccessary
before returning it, so there is no need to call C<update()> manually.

If an error occured while hashing the file, will return a reference to the
error message.

=head2 error

Returns a potential error message or the empty string for no error.

=head2 compare

	$hash->compare($other_hash);

Compares the both hashes and returns true if they are equal. Use this
over a plain C<eq> because this can also work when different hash
algorithmns are in use.

=head1 BUGS

=over 2

=item *

If you copy over the file a file with the same size and same time stamp,
but different contents, then the file will not be re-hashed, thus the change
cannot be detected. (use inode time to prevent this when possible?)

=back

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2008

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.bund.de/> for more information.

=cut

