#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 80;
  }

#############################################################################
# three empty subclasses based on Dicop::Item

require "common.pl";

use Dicop::Item;
use Dicop::Item::Template;
use Math::BigInt;
use Math::BigFloat;

use Dicop::Request::Pattern;
use Dicop::Request;

can_ok ('Dicop::Item', qw/
  fields
  _load_templates _from_string_form _get_template
  /);

my $item = new Dicop::Item ( 
  name => 'test',
  foo => 9,
  blah => 7 );
my $item2 = new Dicop::Item ( 
  name => 'test2',
  foo => 19,
  blah => 57 );

# we did survive until here

my $string = $item->as_string();
my $two = Dicop::Item::from_string($string);

my $keys = 0;	
foreach (keys %$two)
  {
  $keys ++ unless /^_/; # skip internals
  }

# after as_string, the string was cached
is ($item->get('_last_as_string'), Dicop::Base::time(), 'time');
is ($item->get('_last_string'), $two->as_string(), 'one and two are twins');
is ($item->get('_last_string'), $item->as_string(), 'item is ok');
is ($item->error(), '', 'no error');
is ($item->template(), undef, 'no template');
is ($two->error(), '', 'no error');

is (scalar $item->fields(), undef, 'not known since no template');
is (scalar $two->fields(), undef, 'not known since no template');

is ($item->get('id'),1, 'is is 1');
is ($keys,3 + 2, "2 keys because we have 'dirty' and 'id' as default in there");

is ($item->get_as_string('id'),1, 'id is 1');
is ($item->get_as_hex('id'),1, "same as get_as_string unless overwritten");

is (ref($two),'Dicop::Item', 'ref');
is ($two->as_string(),$string, 'as_string() twins');

my $string2 = $item2->as_string(); $string .= $string2;

my @both = Dicop::Item::from_string($string);

is (@both,2, 'got two');

$two = $both[1];
is (ref($two),'Dicop::Item', 'ref');
is ($two->as_string(),$string2, 'string2 is identical');

$two = new Dicop::Item ( 
  name => 'test',
  foo => 9,
  blah => 7, count => Math::BigInt->new(123), 
  verifiers => [ [123], [345], [567] ],
  );

my $evil_twin = $two->copy();

is ($evil_twin->as_string(), $two->as_string(), 'evil twin is evil er ok');

$item = new Dicop::Item ( 
  1 => Math::BigInt->new(1),
  2 => Math::BigFloat->new(2),
  3 => '3',
  4 => [ [ 1,2,3], [ 4,5,6 ] ],
  5 => { 123 => [ 123, 1,2,3], 456 => [ 123, 4,5,6 ] },
  6 => [ 1, 2, 3 ],
  7 => { 123 => 123, 456 => 124 },
  8 => bless { id => 123 }, 'Dicop::Data::Foo',
  );

for my $i (1..8)
  {
  is (ref($item->get($i)), '', "empty");
  }

for my $i (1..3)
  {
  is ($item->get($i), $i, "is $i");
  }

is ($item->get(4),'1_2_3,4_5_6', "1..6");
is ($item->get(5),'123_1_2_3,456_4_5_6', "1..3");
is ($item->get(6),'1,2,3', "1..3");
is ($item->get(7),'123_123,456_124',"is 123");
is ($item->get(8), 123, 'is 123');
isnt ($item->{_modified}, 0, '_modified got set');
is ($item->{_modified}, Dicop::Base::time(), '_modified got set');

my $one;
($one,$two) = Dicop::Item::from_string(
  " {\n match => 'foo'\n".
  " type => 'status'\n}\n".
  " Dicop::Request {\n data => 'cmd_status;'\n".
  " id => 123\n}\n",
  "Dicop::Request::Pattern",
  );

is (ref($one), "Dicop::Request::Pattern", 'default class worked');
is (ref($two), "Dicop::Request", 'and did not interfere');

#############################################################################

$two = Dicop::Item::from_file('testitem.txt');

is (ref($two), 'Dicop::Item');

#############################################################################
my $item_a = new Dicop::Data::Subclass ( name => 'testa' );
my $item_b = new Dicop::Data::Subclass::Sub ( name => 'testb' );
my $item_c = new Dicop::Data::SomeSubclass ( name => 'testc' );

# item_a and item_b must share the ID space, but item_c not
is (ref($item_a), 'Dicop::Data::Subclass', 'new seemed to work');
is (ref($item_b), 'Dicop::Data::Subclass::Sub', 'new seemed to work');
is (ref($item_c), 'Dicop::Data::SomeSubclass', 'new seemed to work');

is ($item_a->{id}, 1, ' space starts with ID 1');
is ($item_b->{id}, 2, ' share the space');
is ($item_c->{id}, 1, ' separate space');

#############################################################################
# trial: read in object definitions

my $templates = [ Dicop::Item::from_file ( 'def/objects.def', 
  'Dicop::Item::Template' ) ];

foreach my $p (@$templates)
  {
  is (ref($p),'Dicop::Item::Template', 'new seemed to work');

  $p->_construct();
  # check for errors
  is ($p->error(), '', 'construct worked w/t error');

  }

#############################################################################
# real load: read in object definitions

my $tpl = Dicop::Item::_load_templates('def/objects.def');
# templates are now loaded and in effect

my $t = Dicop::Item::template('Dicop::Item::Subclass');
is (ref($t), 'Dicop::Item::Template', "Dicop::Item::Template('classname') works");
is ($t->{class}, 'Dicop::Item::Subclass', "Dicop::Item::Template('classname') works");

my $class = 'Dicop::Item::SubSubSubclass';

# check that multiline definition get's loaded properly
is (join(":", sort keys %{$tpl->{$class}}), '_error:_known_fields:_modified:class:description:dirty:fake_keys:fields:help:id:include', '11 keys');
is (join(":", sort keys %{$tpl->{$class}->{fields}}), 'description:name', '2 keys in fields');

$class = 'Dicop::Item::Subclass';

is (join(":", sort keys %{$tpl->{$class}}), '_error:_known_fields:_modified:class:description:dirty:fake_keys:fields:help:id:include', '11 keys');
is (join(":", sort keys %{$tpl->{$class}->{fields}}), 'description:name', '2 keys in fields');

#############################################################################
# _construct()

$item = Dicop::Item::SubSubclass->new();

is (ref($item), 'Dicop::Item::SubSubclass', 'new seemed to work');
is ($item->{myitem}, '1', 'string');

$item->_construct();

is (ref($item->{myitem}), 'Dicop::Data::SomeSubclass', 'ref to obj now');
is (ref($item->{myclass}), 'Math::BigInt', 'ref to bigint');
is ($item->{myclass}, 12, 'is 12');

is (ref($item->{mylist}), 'ARRAY', 'ref to ARRAY');
is (join(":", @{$item->{mylist}}), 'foo:bar', 'foo:bar');

# double construct should do no harm
$item->_construct();

is (ref($item->{myitem}), 'Dicop::Data::SomeSubclass', 'still ref to obj');
is (ref($item->{myclass}), 'Math::BigInt', 'still ref to bigint');
is ($item->{myclass}, 12, 'is 12');

is (ref($item->{mylist}), 'ARRAY', 'ref to ARRAY');
is (join(":", @{$item->{mylist}}), 'foo:bar', 'foo:bar');

is ($item->get_as_string('mylist'), 'foo, bar', 'foo, bar from list');

#############################################################################
# get_as_string()

unlike ($item->get_as_string('mytime'), qr/^\d+$/, 'is not like 123445678 (instead localtime)');

#############################################################################
# highest_id, set_id

is (Dicop::Item::_highest_id('Dicop::Data::Subclass'), 2, 'highest id 2');
is (Dicop::Item::_highest_id('Dicop::Data::Subclass::Sub'), 2, 'highest id 2');

is ($item_a->set_id(4), 4, 'highest id now 4');
is (Dicop::Item::_highest_id('Dicop::Data::Subclass'), 4, 'highest id 4');

# Subclass::Sub share the ID space
is (Dicop::Item::_highest_id('Dicop::Data::Subclass::Sub'), 4, 'highest id 4');

#############################################################################
# error()

is ($item_a->error('test'), 'test', 'setting error works');


