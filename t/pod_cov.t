#!/usr/bin/perl -w

# test POD coverage

use strict;
use Test::More;

BEGIN
   {
   chdir 't' if -d 't';
   use lib '../lib';
   eval "use Test::Pod::Coverage";
   plan skip_all => 'Test::Pod::Coverage not installed on this system' if $@;
   plan tests => 16;
   };

my $trust = { coverage_class => 'Pod::Coverage::CountParents' };

for my $p (qw(
  Dicop::Base
  Dicop::Cache
  Dicop::Client::LWP
  Dicop::Client::wget
  Dicop::Cache
  Dicop::Config
  Dicop::Connect
  Dicop::Event
  Dicop::Handler
  Dicop::Hash
  Dicop::Item
  Dicop::Item::Template
  Dicop::Mail
  Dicop::Request
  Dicop::Request::Pattern
  Dicop::Security
  ))
  {
  pod_coverage_ok( $p, $trust, "$p is covered");
  }
