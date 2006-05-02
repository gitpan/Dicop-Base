#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 2;
  }

require 'daemon';

is (1,1, 'require worked');	# require worked

can_ok ('DICOPD', qw/process_request oops pre_loop_hook output accept/);

1; # EOF

