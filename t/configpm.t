#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 13;
  }

use Dicop::Config;

my $config = new Dicop::Config ( 'test.cfg' );

my $keys = 0;
foreach (keys %$config)
  { 
  $keys++ unless /^_/;
  }
is ($keys, 6, '6 keys');
is ($config->{foo}, 8, '8 foo');
is ($config->{blah}, 9, '9 blah');
is ($config->{name}, "Test name");
is ($config->{some_var}->[0], 7, 'some_var 0');
is ($config->{some_var}->[1], 9, 'some_var 1');
is ($config->{_modified}, 0, 'not modified yet');

$config->set( 'foo' => 'bar');
is ($config->{foo},'bar');
is ($config->{_modified}, 1, 'modified');

# test whether previous uses destroy $/
$config = new Dicop::Config ( 'client.cfg' );
is ($config->{msg_dir}, '../msg');
$keys = 0;
foreach (keys %$config)
  { 
  $keys++ unless /^_/;
  }
is ($keys, 5, '5 keys');

#############################################################################
# allowed keys

my $check = $config->check ( { 
  log_dir => 'dir',
  msg_dir => 'dir',
  error_log => 'file',
  worker_dir => 'dir',
  id => 'int',
  } );

is ($check, undef, 'no error');

is ($config->type('id'), 'int', 'type of id is int');

1; # EOF

