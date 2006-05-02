#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 8;
  }

require 'basics';

is (1,1, 'require worked');	# require worked

can_ok ('main', qw/
	is_root_user check_user_and_group make_config
	get_uid get_gid set_gid set_uid
	/);

#############################################################################
# make config

my $cfg = { proto => 'ssl', host => '*', port => 1234, user => 'dicop',
		group => 'user', chroot => '.', };

my $new = make_config($cfg);

foreach my $k (keys %$cfg)
  {
  is ($new->{$k}, $cfg->{$k}, $k);
  }

1; # EOF

