#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../../lib', '../lib';
  chdir 't' if -d 't';
  plan tests => 31;
  }

use Dicop::Event;
use Dicop::Request;

Dicop::Event::load_messages("msg/messages.txt");

use Dicop::Request::Pattern;

my $pattern = new Dicop::Request::Pattern (
  match => 'cmd_auth',
  opt => 'arch, id, version, fan, temp',
  title => 'Default status',
  sort => 'down',
  );
$pattern->_construct();

my $pattern2 = new Dicop::Request::Pattern (
  match => "cmd_change;type_testcase",
  req => "id,jobtype,charset,end,start,target,description",
  opt => "result,style,prefix,disabled,extra0,extra1,extra2,extra3,extra4,extra5,extra6,extra7",
  title => "Testcase successfully edited",
  tpl => "changed.txt",
  class => "admin",
  auth => 1,
  type => "status",
  );

$pattern2->_construct();

my $pattern3 = new Dicop::Request::Pattern (
  match => "cmd_status;type_jobs",
  opt => "style,sort,sortby",
  title => "Show jobs",
  tpl => "jobs.txt",
  class => "admin",
  auth => 1,
  type => "status",
  sort => "down",
  sortby => "id",
  );

$pattern3->_construct();

can_ok ('Dicop::Request', 
 qw/type template_name template output title pattern auth check new _init
	is_form is_request is_auth is_info
	/);

##########################################################################
# general request tests

my $request = new Dicop::Request ( 
   id => 'req0001', 
   data => 'cmd_auth;arch_win32;id_5;version_0.24;fan_5360;temp_45.1',
   patterns => [ $pattern ], 
  );
is ($request->error(), "", 'no error');

is (join(":",$request->fields()), "arch:cmd:fan:id:temp:version", 'fields()');

my $keys = 0;
foreach (keys %$request)
  { 
  $keys++ unless /^_/;
  }
is ($keys, 6+1, " we also have 'dirty' in there");
is ($request->{id}, 5, 'id is 5');
is ($request->{version}, 0.24, 'version 0.4');
is ($request->{fan}, 5360, '5360 rpm');
is ($request->{temp}, 45.1, 'temp');
is ($request->{cmd}, 'auth', 'auth');
is ($request->{arch}, 'win32', 'os');

is ($request->auth(), 1, 'no auth');
is ($request->class(), 'admin', 'admin');
is ($request->type(), 'status', 'status');
is ($request->template_name(), 'unknown.txt', 'template file name');
is ($request->template(), undef, 'no template for this class');
is (join(":",$request->sort_order()), 'down:id', 'sort order default: down, id');

###############################################################################
# empty param results in '' not undef

$request = new Dicop::Request ( 
   id => 'req0001', 
   data => 'cmd_auth;arch_win32;id_5;version_0.24;fan_;temp_45.1',
   patterns => [ $pattern ], 
  );
is ($request->error(), "", 'no error');
is ($request->{fan}, '', 'fan is empty');

###############################################################################
# test changing id

is ($request->request_id(), 'req0001', 'id');
$request->field('_id','req0002');
is ($request->request_id(), 'req0002', 'now 0002');
$request->request_id('req0003');
is ($request->request_id(), 'req0003', 'now 0003');
$request->request_id('abc0004');
is ($request->request_id(), 'req0003', 'still 0003');

###############################################################################
# test request with empty value (and making a copy of it)

my $data = 'charset_1;cmd_change;description_test;disabled_;end_41414141;id_1;jobtype_1;prefix_;result_4142;start_4141;target_414244;type_testcase';
$request = new Dicop::Request ( id => 'req0001',
   data => $data,
   patterns => [ $pattern2 ]);
 
if (!is ($request->error(),""))
  {
  print "# Failed for request: '$data'\n";
  }
# copy() and compare
is ($request->copy()->as_request_string(),$request->as_request_string(), 'copy');

is ($request->as_request_string(), "req0001=$data", 'preserves empty params');
is ($request->copy()->as_request_string(), "req0001=$data", 'copy');

###############################################################################
# sort orders and overriding

$request = new Dicop::Request ( id => 'req0001',
   data => 'cmd_status;type_jobs;style_foo',
   patterns => [ $pattern3 ]);

# default
is (join(":",$request->sort_order()), 'down:id', 'sort order default: down, id');

# request override sort direction

$request = new Dicop::Request ( id => 'req0001',
   data => 'cmd_status;type_jobs;style_foo;sort_up',
   patterns => [ $pattern3 ]);

# default
is (join(":",$request->sort_order()), 'up:id', 'sort order: up, id');

# request override sort direction and sort by field

$request = new Dicop::Request ( id => 'req0001',
   data => 'cmd_status;type_jobs;style_foo;sort_up;sortby_name',
   patterns => [ $pattern3 ]);

# default
is (join(":",$request->sort_order()), 'up:name', 'sort order: up, name');


# request override sort direction and sort by field (cmp)

$request = new Dicop::Request ( id => 'req0001',
   data => 'cmd_status;type_jobs;style_foo;sort_upstr;sortby_name',
   patterns => [ $pattern3 ]);

# default
is (join(":",$request->sort_order()), 'upstr:name', 'sort order: upstr, name');

# request override sort direction (wrongly, thus ignored) and sort by field (cmp)

$request = new Dicop::Request ( id => 'req0001',
   data => 'cmd_status;type_jobs;style_foo;sort_upcmp;sortby_name',
   patterns => [ $pattern3 ]);

# default
is (join(":",$request->sort_order()), 'down:name', 'sort order: down, name');



1; # EOF

