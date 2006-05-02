#!/usr/bin/perl -Tw

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 9;
  }

use Dicop::Item;
use Dicop::Item::Template;

can_ok ('Dicop::Item', qw/_load_templates/);

my $item = new Dicop::Item ( 
  name => 'test',
  foo => 9,
  blah => 7 );

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

