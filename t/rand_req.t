#!/usr/bin/perl -w

# generate random request strings and test them

use Test;
use strict;

my $tests;

BEGIN
  {
  unshift @INC, '../../lib', '../lib';
  chdir 't' if -d 't';
  $tests = 128;
  plan tests => $tests * 2;
  }

my $DEBUG = 0;

use Dicop::Event;
use Dicop::Request;

Dicop::Event::load_messages("msg/messages.txt") or die();

my $keywords = [ qw/
  add
  cmd
  client
  clientmap
  confirm
  config
  del
  description
  dicop
  data
  form
  group
  help
  id
  job
  jobtype
  list
  main
  name
  result
  proxy
  status
  style
  submit
  testcase
  user
  ;
  =
  +
  &
  ?
  -
  _
  |
  /, ' ', ];

my $seed = int(rand(2147483647));
srand($seed);

print "# seed: $seed\n";

# chaotig data
for (1 .. $tests)
  {
  my $len = rand(768);
  $len = rand(42) if $_ < 42;	# some more short ones

  my $data = ''; 
  while (length($data) < $len)
    {
    $data .= randword();
    $data .= 's' if rand() < 0.10;	# 10% probability of 'client' => 'clients' etc
    $data .= '_' if rand() < 0.10;	# 10% probability of additonal '_'
    }
  print "# '$data'\n" if $DEBUG;
  my $request;
  eval {
    $request = new Dicop::Request ( 
       id => 'req0001', 
       data => $data,
      );
    };
  ok ($@, '');
  }

# "well-formed" data

for (1 .. $tests)
  {
  my $len = rand(768);
  $len = rand(42) if $_ < 42;	# some more short ones

  my $data = 'cmd_' . randword() . ';type_' . randword();

  print "# '$data'\n" if $DEBUG;
  my $request;
  eval {
    $request = new Dicop::Request ( 
       id => 'req0001', 
       data => $data,
      );
    };
  ok ($@, '');
  }

sub randword
  {
  $keywords->[ rand( scalar @$keywords ) ];
  }

