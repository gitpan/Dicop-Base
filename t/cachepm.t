#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 63;
  use_ok ('Dicop::Cache');
  }

can_ok ("Dicop::Cache", qw/
  oldest
  get_oldest
  get
  put
  touch
  get_time
  items
  purge
  clean
  limit
  timeout
  statistics
 /);

use Dicop::Base;

#################################################################################
# new()

Dicop::Base::cache_time();

# defaults
my $cache = Dicop::Cache->new ( );
is (ref($cache),'Dicop::Cache', 'ref');
is ($cache->timeout(),3600*6, 'timeout');
is ($cache->limit(), undef, 'no limit');
is ($cache->{oldesttime},0, 'oldesttime');
is ($cache->{oldestthing}, undef, 'oldestthing');

my $stats = $cache->statistics();

is ($stats->{hits}, 0, 'no hits yet');
is ($stats->{gets}, 0, 'no gets yet');
is ($stats->{puts}, 0, 'no puts yet');
is ($stats->{misses}, 0, 'no misses yet');

$cache = Dicop::Cache->new ( timeout => 1200 );
is (ref($cache),'Dicop::Cache');
is ($cache->timeout(),1200, '1200s');
is ($cache->limit(), undef, 'no limit');

$cache = Dicop::Cache->new ( limit => 9 );
is (ref($cache),'Dicop::Cache', 'ref');
is ($cache->timeout(),3600*6, '6 hours');
is ($cache->limit(),9, '9 items');

$cache = Dicop::Cache->new ( timeout => 1400, limit => 19 );
is ($cache->items(),0, 'no items');
is (ref($cache),'Dicop::Cache','ref');
is ($cache->timeout(),1400, 'timeout');
is ($cache->limit(),19, 'limit');

$cache = Dicop::Cache->new ( timeout => 5, limit => 5 );
is (ref($cache),'Dicop::Cache','ref');

is ($cache->items(),0, 'no items');
is ($cache->oldest(), undef, 'no oldest yet');

my $time = Dicop::Base::time;
is ($cache->put( foo => 'bar'),1, 'put one in');
is ($cache->{time}->{foo} == $time, 1, 'foo has correct time');
is ($cache->items(),1, 'one item');
is ($cache->oldest(),'foo', 'foo is oldest');

$time = $cache->{time}->{foo};
is ($cache->get_time('foo'),$time, 'get_time');
is ($cache->items(),1, 'still one item');

# put/get
is ($cache->put( baz => [ 'duh', 'blah' ]),2, '2 items');
is (ref($cache->get('baz')),'ARRAY', 'baz is array'); 
is ($cache->get('foo'),'bar', 'got foo bar'); 

# force timeout on foo
$cache->{time}->{foo} -= 10;				# timeout is 5
is ($cache->get('foo'), undef, 'foo is gone now');
is ($cache->items(),1, 'only one item left');

# see if purge/items work
is ($cache->put( foo => 'bar'),2, 'put one in again');
$cache->{time}->{foo} -= 10;				# timeout is 5
$cache->{oldesttime} = $cache->{time}->{foo};
is ($cache->items(),1, 'only one left');

is ($cache->put( foo => 'bar'),2, 'in again');
$cache->{time}->{foo} -= 10;				# timeout is 5
$cache->{oldesttime} = $cache->{time}->{foo};
is ($cache->purge(),1, 'only one left');

# purge with item count limit
$cache = Dicop::Cache->new ( timeout => 5, limit => 3 );
is ($cache->items(), 0, 'none yet');
for (1 .. 4)
  {
  $cache->put( "foo $_" => "bar");
  }
is ($cache->items(),3, 'only 3 left');

###############################################################################
# cleaning

$cache->clean();
is ($cache->items(),0, 'none left');
is ($cache->{oldestthing}, undef, 'no oldest');
is ($cache->{oldesttime},0, 'no oldest time');
is (ref($cache->{cache}),'HASH', 'cache is a hash');
is (ref($cache->{time}),'HASH', 'time is a hash');
is (scalar keys %{$cache->{cache}},0, 'no keys in cache');
is (scalar keys %{$cache->{time}},0,'no keys in time');

###############################################################################
# touch

is ($cache->put( foo => [ 'duh', 'blah' ]),1, 'one item');
is (ref($cache->get('foo')),'ARRAY', 'foo in cache'); 
$cache->put( baz => [ 'duh', 'blah' ]);

# make them older
$cache->{time}->{foo} -= 4;
$cache->{time}->{baz} -= 2;
$cache->{oldesttime} = $cache->{time}->{foo};

# check it
is (ref($cache->get('foo')),'ARRAY', "get doesn't touch it");
is ($cache->{oldesttime},$cache->{time}->{foo}, 'foo oldest');
is ($cache->oldest(),'foo', 'foo is oldest');
is (ref($cache->get_oldest()), ref($cache->get('foo')), ' foo is oldest');

# touch it
is (ref($cache->touch('foo')),'ARRAY', "touch it to make youngest");
is ($cache->{oldesttime} < $cache->{time}->{foo}, 1, 'oldesttime < foo');
is ($cache->get_time('foo'),$cache->{time}->{foo}, 'foo is foo');
is ($cache->oldest(), 'baz', ' baz is older than foo');
is (ref($cache->get_oldest()), ref($cache->get('baz')), ' baz is oldest');

###############################################################################
# setting a new limit()

# put some in

is ($cache->put( foo => [ 'duh', 'blah' ]),2, 'one item');
is ($cache->put( magic => 'nocando' ),3, 'one more');
is ($cache->items(), 3, 'have three now');

$cache->limit(2);
is ($cache->items(), 2, 'have two now');

1; # EOF

