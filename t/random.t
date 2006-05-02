#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 3;
  }

use Dicop::Base qw/random/;

################################################################################
# random()

my $buffer = random();
is (length($buffer),int(128/8), 'buffer length is 128/8');
$buffer = random(10);
is (length($buffer),int(10/8), 'buffer lenght is 10/8');

# this is not a true test for randomness, but make at least shure we don't get
# things like sixteen spaces or some other sillyness

$buffer = random(128); my @chars = split //, $buffer;

my %hash = map { ord($_) => 1 } split //, $buffer;

# at least 10 different bytes
is (scalar keys %hash >= 10, 1, 'more than 10 different bytes');

1; # EOF

