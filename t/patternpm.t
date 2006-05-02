#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../../lib', '../lib';
  chdir 't' if -d 't';
  plan tests => 35;
  }

use Dicop::Event;
use Dicop::Request::Pattern;
use Dicop::Request;
use Dicop::Item;

Dicop::Event::load_messages("msg/messages.txt") or die();

can_ok ('Dicop::Request::Pattern', 
  qw/title template template_name output type match _init new auth/);

#############################################################################
# general request pattern tests

my $pat = new Dicop::Request::Pattern ( 
  match => 'cmd_status;type_main',
  title => 'Default status',
  );
$pat->_construct();
is ($pat->error(),"", 'no error');

# test default values
is ($pat->type(), 'status', 'type is status');
is ($pat->output(), 'html', 'output id html');
is ($pat->template_name(), 'main.tpl', 'main.tpl');
is ($pat->title(), 'Default status', 'title');
is ($pat->auth(), 1, 'no auth per default');
is (join(":",$pat->sort_order()), 'up:id', 'up:id');

#############################################################################
# pattern with ##request-field##

$pat = new Dicop::Request::Pattern ( 
  match => 'cmd_status;type_main',
  title => 'Default ##request-type## status',
  tpl => 'status_##request-type##.tpl',
  );
$pat->_construct();
is ($pat->error(),"", 'no error');

# test default values
is ($pat->type(), 'status', 'type is status');
is ($pat->output(), 'html', 'output id html');
is ($pat->template_name(), 'status_.tpl', 'status_.tpl');
is ($pat->title(), 'Default  status', 'title');
is ($pat->auth(), 1, 'no auth per default');

# try to construct reconstruct request patterns from a file

my $file = 'def/request.def';
my $file_data;

{
  open FILE, $file or die ("Cannot read $file: $!");
  local $/ = undef;
  $file_data = <FILE>;
  close FILE;
}

my @patterns = Dicop::Item::from_string ($file_data, 'Dicop::Request::Pattern');
foreach my $p (@patterns)
  {
  $p->_construct();
  }

my $cnt = 6;
is (scalar @patterns, $cnt, "$cnt sample patterns");

is (ref($patterns[0]), 'Dicop::Request::Pattern', 'new was ok');

for (my $k=0; $k < $cnt; $k++)
  {
  is ($patterns[$k]->error(), '', 'no error');
  is ($patterns[$k]->auth(), 0, 'no auth') if $k != 0;
  }

############################################################################
# pattern match test

# positive tests
my $req = 
  Dicop::Request->new ( id => 'req0001', data => 'cmd_help;type_news',
  patterns => \@patterns );

is ($req->error(), '', 'no error - matched');

$req = 
  Dicop::Request->new ( id => 'req0001', data => 'cmd_foo;type_bar',
  patterns => \@patterns );

is ($req->error(), '', 'no error - matched');
is ($req->title(), 'FooBar without ID', 'FooBar without ID');

$req = 
  Dicop::Request->new ( id => 'req0001', data => 'cmd_foo;type_bar;id_123',
  patterns => \@patterns );

is ($req->error(), '', 'no error - matched');
is ($req->title(), 'FooBar with ID', 'FooBar with ID');

############################################################################
# negative tests

# empty param
$req = Dicop::Request->new ( id => 'req0001', data => 'cmd_help;type_',
  patterns => \@patterns );

print "# Got: ".$req->error() unless
  is ($req->error() =~ /req0001 462 Invalid request - no request pattern matched/, 1, 'error - not matched');

# additional param
$req = Dicop::Request->new ( id => 'req0001', data => 'cmd_help;type_news;foo_bar',
  patterns => \@patterns );

print "# Got: ".$req->error() unless
  is ($req->error() =~ /req0001 460 Parameter 'foo' \('bar'\) not allowed in request/, 1, 'error - not matched');

# negative match
$req = Dicop::Request->new ( id => 'req0001', data => 'cmd_foo;type_baz',
  patterns => \@patterns );

print "# Got: ".$req->error() unless
  is ($req->error() =~ /req0001 450 Malformed request: 'Request baz not allowed'/, 1, 'error - baz not allowed');

1; # EOF

