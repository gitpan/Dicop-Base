#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  plan tests => 2;
  chdir 't' if -d 't';
  use_ok ('Dicop::Connect');

  }

can_ok ('Dicop::Item', qw/_connect_server _load_connector/);

