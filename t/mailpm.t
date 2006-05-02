#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 2;

  use_ok('Dicop::Mail');
  }

can_ok('Dicop::Handler', qw/ flush_email_queue /);

1; # EOF

