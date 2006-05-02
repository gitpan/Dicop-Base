#!/usr/bin/perl -Tw

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 42;
  use_ok ('Dicop::Item::Template');
  }

use Math::BigInt;

package Dicop::Item::SubSubclass;

use base qw/Dicop::Item/;

1;

package Dicop::Item::Subclass;

use base qw/Dicop::Item/;

1;

package Dicop::Handler::Foo;

use base qw/Dicop::Item/;

1;

package main;

can_ok ('Dicop::Item::Template', qw/
   init_object can_change error check_field construct_field
   editable_fields field addable_fields fields
   description help include fields_of_type
  /);

my $template = Dicop::Item::Template->new();

is (ref($template), 'Dicop::Item::Template', 'new seemed to work');

is ($template->description(), '', 'no description per default');
is ($template->help(), 'No further help available.', 'help text');

my $tpl = Dicop::Item::_load_templates('def/objects.def');
# templates are now loaded and in effect

#############################################################################
# construct test object

my $obj = Dicop::Item::SubSubclass->new();
is (ref($obj), 'Dicop::Item::SubSubclass');


# XXX TODO: put these examples in DATA like 'ip|127.0.0.1|127.0.0.1'

my $val = Dicop::Item::_check_field($obj,'some_int', 3.14);
is ($val, 5, '3.14 is 3 as int, but min says it must be at least 5');

$val = Dicop::Item::_check_field($obj,'some_int', 6.14);
is ($val, 6, '6.14 is 6 as int');

$val = Dicop::Item::_check_field($obj,'some_int', 12.14);
is ($val, 9, '12.14 is 12, but max says it is max 9');

$obj->template()->construct_field($obj,'myclass');

$val = Dicop::Item::_check_field($obj,'myclass', 1);
is ($val, 8, '1 is 1 as int, but min says it is 8');
is (ref($val), 'Math::BigInt', 'class is preserved');

$val = Dicop::Item::_check_field($obj,'myclass', 14);
is ($val, 13, '14 is 14 as int, but max says it is 13');
is (ref($val), 'Math::BigInt', 'class is preserved');

for my $f (qw/myip mymask/)
  {
  $val = Dicop::Item::_check_field($obj, $f, '127.0.0.1');
  is ($val, '127.0.0.1', '127.0.0.1');
  $val = Dicop::Item::_check_field($obj, $f, ' 127.0.0.1 ');
  is ($val, '127.0.0.1', ' " 127.0.0.1 " => "127.0.0.1"');
  $obj->{_error} = '';
  $val = Dicop::Item::_check_field($obj, $f, ' 1.2.3.4.5 ');
  is ($obj->{_error}, "'1.2.3.4.5' is not a valid IP or netmask.", 'error');
  }

# IPv6 not supported yet
#$val = Dicop::Item::_check_field($obj,'ip', 'FFFF:0');
#is ($val, 'FFFF:0', 'FFFF:0');

is (join(":", $obj->template()->editable_fields()), 'description:myip:mymask:name:some_int', 'editable fields');
is (join(":", $obj->template()->addable_fields()), 'description:my_virt:some_int', 'addable fields (including virtual)');
is (join(":", $obj->template()->changeable_fields()), 'changer', 'changeable fields');

is ($obj->template()->field('changer')->{noadd}, 1, 'changeable fields are automatically noadd');

is (ref($obj->template()->field('description')), 'HASH', 'field()');
is ($obj->template()->field('description')->{minlen}, undef, 'minlen is undef');
is ($obj->template()->field('description')->{maxlen}, 256, 'maxlen is 256');

# space as delimiter for fake_keys:
$obj = Dicop::Item::Subclass->new();
is (ref($obj), 'Dicop::Item::Subclass');

is (join(":", $obj->template()->fields()), 'description:id:more:name:size', 'template->fields');
is (join(":", $obj->fields()), 'description:id:more:name:size', 'obj->fields');

# #description/addoption/editoption
$obj = Dicop::Handler::Foo->new();
is (ref($obj), 'Dicop::Handler::Foo', 'foo constructed');

my $field = $obj->template()->field('some_optional');
is (ref($field), 'HASH', 'got "field some_optional"');
is (ref($field->{addoption}), 'HASH', 'got addoption');
is ($field->{addoption}->{0}, 'More', 'got addoption key 0');
is (ref($field->{editoption}), 'HASH', 'got editoption');
is ($field->{editoption}->{0}, 'More', 'got editoption key 0');

$field = $obj->template()->field('some_int');
is (ref($field), 'HASH', 'got "field some_int"');
is ($field->{description}, 'Some text here', 'description ok');

#############################################################################
# fields_of_type()

is (join(":", $obj->template()->fields_of_type('bool')), '', 'bool');
is (join(":", $obj->template()->fields_of_type('int')), 'some_more_int:some_optional', 'int');
is (join(":", $obj->template()->fields_of_type('foo')), '', 'foo');

#############################################################################
# test that fields() does not return 'virtual' fields and no doubles

$obj = Dicop::Item::SubSubclass->new();
is (ref($obj), 'Dicop::Item::SubSubclass');
is (join(":", $obj->template()->fields()), 'changer:description:id:myclass:myip:myitem:mylist:mymask:mytime:name:size:some_int:supersize', 'no doubles');

