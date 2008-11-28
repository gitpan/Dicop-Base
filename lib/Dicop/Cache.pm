#############################################################################
# Dicop::Cache -- manage caches with timeout
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2008
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Cache;
use vars qw($VERSION);
$VERSION = 1.04;	# Current version of this package
require  5.008001;	# requires this Perl version or later

use strict;
use Dicop::Base;		# for time()
use Math::BigInt try => 'GMP';	# for counters

sub new
  {
  # create a new cache, parameter hash with:
  # timeout => in_seconds, items => max_number
  my $class = shift;
  $class = ref($class) || $class || __PACKAGE__;
  my $self = {};
  bless $self, $class;
  $self->_init(@_);
  }
 
sub _init
  {
  # initialize the cache
  my $self = shift;
  
  my $args;
  if (ref($_[0]) ne 'HASH')
    {
    $args = { @_ };
    }
  else
    {
    $args = shift;
    }
  
  $self->{timeout} = $args->{timeout} || 6*3600;	# six hours
  $self->{limit} = $args->{limit};			# undef for no limit

  foreach my $arg (keys %$args)
    {
    next if $arg =~ /^(limit|timeout)\z/;		# valid
    require Carp;
    Carp::croak("Unknown option '$arg' for Dicop::Cache->new");
    }

  $self->clean();
  }

sub get
  {
  # retrieve an item, returns undef if not present
  my ($self,$key) = @_;

  $self->{gets}->binc();

  if (!defined $key || !exists $self->{cache}->{$key})
    {
    $self->{misses}->binc();
    return undef;
    }

  # for performance reasons, leave other too old entries intact (you can't get
  # them anyway, get()/get_time() would kill them first, as would items()
  if ((Dicop::Base::time() - $self->{time}->{$key}) > $self->{timeout})
    {
    # if to old, purge from cache
    delete $self->{cache}->{$key};
    delete $self->{time}->{$key};
    $self->{misses}->binc();
    return undef;
    }
  $self->{hits}->binc();
  $self->{cache}->{$key};
  }

sub touch
  {
  # update the time on an item to now (making it expire later), returns the
  # item or undef
  my ($self,$key) = @_;

  return undef unless defined $key && exists $self->{cache}->{$key};

  # make current time
  $self->{time}->{$key} = Dicop::Base::time();
  
  # If we did not touch the oldest element, it will stay the oldest
  $self->_find_oldest()
    if ($self->{oldesttime} != 0 && $self->{oldestthing} eq $key);

  $self->{cache}->{$key};
  }

sub _find_oldest
  {
  my $self = shift;

  my $t = $self->{time};
  my $oldesttime = Dicop::Base::time();
  my $oldestthing = $self->{oldestthing};
  foreach my $key (keys %$t)
    {
   if ($t->{$key} < $oldesttime)
      {
      $oldesttime  = $t->{$key};
      $oldestthing = $key;
      }
    }
  $self->{oldesttime} = $oldesttime;
  $self->{oldestthing} = $oldestthing;
  
  $self;
  }

sub get_time
  {
  # retrieve insertion time of an item, returns undef if not present
  my ($self,$key) = @_;

  return undef unless defined $key && exists $self->{cache}->{$key};
  
  # for performance reasons, leave other too old entries intact (you can't get
  # them anyway, get()/get_time() would kill them first, as would items()
  if ((Dicop::Base::time() - $self->{time}->{$key}) > $self->{timeout})
    {
    # if to old, purge from cache
    delete $self->{cache}->{$key};
    delete $self->{time}->{$key};
    return undef;
    }
  $self->{time}->{$key};
  }

sub put
  {
  # put an item into the cache (does only put a shallow reference, not a copy)
  my ($self,$key,$item) = @_;

  $self->{puts}->binc();
  return undef unless defined $key;
  
  $self->{cache}->{$key} = $item;
  $self->{time}->{$key} = Dicop::Base::time();
  if ($self->{oldesttime} == 0)
    {
    # not yet defined
    $self->{oldesttime} = $self->{time}->{$key};
    $self->{oldestthing} = $key;
    }
  $self->purge();	# if too much or too old ones, clean yourself
  }

sub purge
  {
  # purges all old items, and keep not more than $limit items
  # returns number of items left
  my $self = shift;

  my $keys = scalar keys %{$self->{time}};
  return 0 if $keys == 0;				# cache empty anyway

  my $bordertime = Dicop::Base::time() - $self->{timeout};

  # need to purge older items?
  if ($self->{oldesttime} < $bordertime)
    {
    foreach my $key (sort { $self->{time}->{$a} <=> $self->{time}->{$b} }
     keys %{$self->{time}})
      {
      if ($self->{time}->{$key} > $bordertime)
	{
	$self->{oldesttime} = $self->{time}->{$key};	# oldest to survive
	$self->{oldestthing} = $key;			# oldest to survive
	last; 						# anything left is kept
	}
      delete $self->{cache}->{$key};
      delete $self->{time}->{$key};
      }
    }

  # after purging old ones, we have some left
  $keys = scalar keys %{$self->{time}};			# how many have we now?
  # if too many, kill oldest ones first
  if (defined $self->{limit} && $keys > $self->{limit})
    {
    my $del = $keys - $self->{limit};			# how many to delete
    # delete oldest first
    foreach my $key (sort { $self->{time}->{$a} <=> $self->{time}->{$b} }
     keys %{$self->{time}})
      {
      if ($del == 0)					# deleted enough ?
	{
	$self->{oldesttime} = $self->{time}->{$key};	# oldest to surviving
	$self->{oldestthing} = $key;			# oldest to surviving
	last; 						# anything left is kept
	}
      delete $self->{cache}->{$key};
      delete $self->{time}->{$key};
      $del--;	
      }
    }
  scalar keys %{$self->{time}};
  }

sub items
  {
  # purge all old items, then return number of items left
  my $self = shift;
 
  $self->purge();
  }

sub oldest
  {
  # return key of oldest item
  my $self = shift;

  $self->{oldestthing};
  }

sub get_oldest
  {
  # return the oldest item
  my $self = shift;
 
  $self->{cache}->{$self->{oldestthing}};
  }

sub timeout
  {
  my $self = shift;
  
  if (defined $_[0] && $self->{timeout} != $_[0])
    {
    $self->{timeout} = shift;
    $self->purge();				# re-adjust
    }
  $self->{timeout};
  }

sub limit
  {
  # get/set the limit e.g.the number of items to keep in the cache
  my $self = shift;
  
  if (@_ > 0)
    {
    if ((!defined $self->{limit}) || (!defined $_[0]) ||
      ( $self->{limit} != $_[0]))
      {
      $self->{limit} = shift;
      $self->purge();				# readjust
      }
    }
  $self->{limit};
  }

sub clean
  {
  # clean all entries from the cache, reset the stats
  my $self = shift;

  $self->{cache} = {};					# empty cache
  $self->{time} = {};					# empty cache
  $self->{oldesttime} = 0;
  $self->{oldestthing} = undef;				# none

  foreach my $k (qw/gets puts hits misses/)
    {
    $self->{$k} = Math::BigInt->bzero();
    }

  $self;
  }

sub statistics
  {
  my $self = shift;

  my $stats = {};
  foreach my $k (qw/gets puts hits misses/)
    {
    $stats->{$k} = $self->{$k}->copy();
    }

  $stats;
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Cache - cache items with timeout and limit

=head1 SYNOPSIS

	use Dicop::Cache;

	my $cache = Dicop::Cache->new( timeout => 3600, items => 12);

	$cache->put (foo => 'bar');
        sleep(2);
        for ($i = 0; $i < 14; $i++)
          {
	  $cache->put ( $i => 'fooo');
          }
	print $cache->items(),"\n";		# will be 12

	my $cache = Dicop::Cache->new( timeout => 2*3600);	# no limit

	my $stats = $cache->statistics();

	print "Hits: $stats->{hits} Misses: $stats->{misses}\n";
	

=head1 REQUIRES

perl5.005, Exporter

=head1 EXPORTS

Exports nothing per default.

=head1 DESCRIPTION

This module keeps a cache of things. The cache has a timeout, anything that is
older will be deleted. In addition it can also have a limit on how many items
it can hold.

Old items will be automatically purged from the cache when you call C<get()>,
C<put()>, C<items()> or C<purge()>.

=head1 METHODS

=head2 new

Create a new cache object. Parameters are as follows:

	timeout		in seconds, time to live for a cache entry
	limit		how many items to keep 

=head2 clean

	$cache->clean();

Clean all entries from the cache, making it an empty cache. It also resets all
the statistics.

=head2 get

	my $item = $cache->get( $key );

Return the item with the key $key from the cache, or undef if it is not in.
See also L<get_time> and L<touch>.

C<get()> does B<NOT> touch an item. If you want to always purge the least
accessed items, do:

	my $item = $cache->get( $key );
	$cache->touch( $key );			# make youngest

=head2 touch

	$cache->touch( $key );
	$item = $cache->touch( $key );

Update the time on an item to now (making it expire later), returns the
item or undef.

=head2 get_time
	
	$cache->get_time( $key );

Return the time of insertion (or the latest touch()) of the item with the
key $key from the cache, or undef if the item is not in the cache. See also
L<get> and L<touch>.

=head2 put

	$cache->put( $key => $value );

Insert the item with the value $value and the key $key into the cache. If the
cache has entries too old or too much entries (exceeding the limit), then it
will be cleaned of these.

=head2 oldest

	$key = $cache->oldest();

Return key of oldest item in cache. To get the actually oldest item, see
L<get_oldest>. If there are no items in the cache yet, will return C<undef>.

=head2 get_oldest

	$elder_one = $cache->get_oldest();

Returns the oldest item in the cache. If the cache is empty, returns undef.

Do B<NOT> use the following:

	$elder_one = $cache->get( $cache->oldest() );	# WRONG!

Because the item that C<< $cache->oldest() >> returns might expire before
the C<< $cache->get( ) >> can retrieve it.

=head2 timeout

	$cache->timeout(3600);
	print $cache->timeout(3600),"\n";

Return and/or set the timeout value of the entries. Any entry older than this
will be purged from the cache.

=head2 limit

	$cache->limit(12);		# set to 12
	print $cache->limit(),"\n";	# print it
	$cache->limit(undef);		# disable limit

Return and/or set the limit aka the maximum allowed number of entrie.

=head2 items

Purge all old items, then return number of items left in cache.

=head2 purge

Purges all old items, and keep not more than L<limit()> items in cache.
Returns number of items left. 

=head2 statistics

	my $stats = $cache->statistics();

Returns a hash ref. The hash contains the following keys:

	hits	 times a get() hit a cached item and returned it
	misses	 times a get() did not find a cached item
	puts	 how many times was put() called
	gets	 how many times was get() called (misses+hits)

=head1 BUGS

=over 2

=item inserting

Inserting more items than $limit at the same time will not properly keep
the oldest (granularity is one second).

=back

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2008

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

