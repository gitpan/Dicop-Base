#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 39;

  use_ok('Dicop::Handler');
  }

can_ok('Dicop::Handler', qw/ 
  _security_checks
  _load_request_patterns
  _load_messages
  _load_object_definitions
  _include_form
  _include_template
  _convert_submit_button
  _option_list
  _start_leak_report
  _end_leak_report
  read_template
  read_table_template
  check
  flush
  _flush_data
  _init
  _construct
  _construct_file_names
  _format_string
  name_from_type
  class_from_type

  check_peer
  authenticate_user
  request_auth

  status
  status_style
  status_config

  _check_templates
  _track_connect
  finish_html_request
  finish_connect
  pre_connect
  get_object
  get_id_list
  AUTOLOAD
  status
/);

#############################################################################
require "common.pl";

is ( join(':', Dicop::Handler->other_request()), 'other:unknown', 'other request');

$Dicop::Handler::NO_STDERR = 1;		# disable informative output

# try to construct object

my $handler = Dicop::Handler->new( cfg_dir => 'test-config' );

is ( ref($handler), 'Dicop::Handler', 'new seemed to work');

is ( join (":", $handler->get_id_list('case')), '', 'no cases');

#############################################################################
# default init

is ($handler->{flush_time}, 0, 'flush_time');
is ($handler->{last_flush}, 0, 'last_flush');
is (@{$handler->{email_queue}}, 0 , 'empty email queue');
is ($handler->{self}, '/' , 'self');

is ($handler->{connects}, 0, 'no connect yet');
is ($handler->{all_connects_time}, 0, 'no connect yet');
is ($handler->{last_connect_time}, 0, 'no connect yet');
is ($handler->{average_connect_time}, 0, 'no connect yet' );

$handler->{connects} = 2;
$handler->_track_connect( '12' );

is ($handler->{all_connects_time}, 12, 'connected');
is ($handler->{last_connect_time}, 12, 'connected');
is ($handler->{average_connect_time}, 6, 'connected' );

#############################################################################
# _format_string()

is ($handler->_format_string('case_url', { name => '1234' }),
  'http://127.0.0.1/show_case?case_nr=1234', '_format_string');

#############################################################################
# _include_form()

my $txt = \"";
$handler->_include_form( $txt, { } );

is ($$txt, '', 'include_form returned w/o error');

$txt = "##add-object-fields##";
my $t = \$txt;

$handler->_include_form( $t, { type => 'Foo' } );

foreach my $name (qw/Description Myip Pwd Pwdrepeat Some_int Name/)
  {
  like ($$t, qr/$name:/, "include_form included $name");
  }
foreach my $name (qw/Some_More_int/)
  {
  unlike ($$t, qr/$name:/i, "include_form does not include $name");
  }

#############################################################################
# _split_submit_button_name()

my $req = "cmd_form;type_testcase;id_3;name_foo;style_blue";
my $name = "submit_cmd_status;type_file;browse_target;path_414141414141=>cmd_form;type_testcase;id_3";

$req = $handler->_convert_submit_button($name,$req);

is ($req, 
  "cmd_status;type_file;browse_target;path_414141414141;form_cmd%5fform%3btype%5ftestcase%3bid%5f3;params_name%5ffoo");

$req = "cmd_form;type_testcase;id_3;name_foo;style_blue;description_bar";
$name = "submit_cmd_status;type_file;browse_target;path_414141414141=>cmd_form;type_testcase;id_3";

$req = $handler->_convert_submit_button($name,$req);

is ($req, 
  "cmd_status;type_file;browse_target;path_414141414141;form_cmd%5fform%3btype%5ftestcase%3bid%5f3;params_name%5ffoo%3bdescription%5fbar");

$req = "cmd_form;type_testcase;id_3;name_foo;style_blue;jobtype_2;description_bar";
$name = "submit_cmd_status;type_file;browse_target;path_414141414141=>cmd_form;type_testcase;id_3";

$req = $handler->_convert_submit_button($name,$req);

is ($req, 
  "cmd_status;type_file;browse_target;path_414141414141;form_cmd%5fform%3btype%5ftestcase%3bid%5f3;params_name%5ffoo%3bjobtype%5f2%3bdescription%5fbar");

# button with "=>" (e.g. empty params, refresh form)

$req = "cmd_add;type_testcase;id_3;name_foo;style_blue;jobtype_2;description_bar";
$name = "submit_cmd_status;type_testcase;=>";

$req = $handler->_convert_submit_button($name,$req);

is ($req, 
  "cmd_status;type_testcase;params_cmd%5fadd%3btype%5ftestcase%3bid%5f3%3bname%5ffoo%3bjobtype%5f2%3bdescription%5fbar",
  'submit button to refresh form');

#############################################################################
# check_peer()

is ($handler->check_peer( '1.2.3.4', '1.2.3.0', '255.255.255.0', 'test'), undef, 'client allowed');
is ($handler->check_peer( '1.2.3.5', '1.2.3.0', '255.255.255.0', 'test'), undef, 'client allowed');
is ($handler->check_peer( '1.2.4.4', '1.2.3.0', '255.255.255.0', 'test'), 
  "457 Your IP '1.2.4.4' does not match the stored IP from client 'test'\n", 'client denied');

#############################################################################
# _option_list()

my $tpl = $handler->read_template('setappform.tpl');
my $res = $handler->_option_list($tpl);

is (ref($res), 'SCALAR', '_option_list returned ref');

$$res =~ s/##param(\d)##/$1/g;		# nix '##param0##'

unlike ($$res, qr/##/, 'no templates left over');
like ($$res, qr/<select name="cset0"/, 'select name got changed properly');
  
###############################################################################
# name_from_type()

is ($handler->name_from_type('job'), 'jobs', 'job => jobs');
is ($handler->name_from_type('proxy'), 'proxies', 'proxy => proxies');
is ($handler->name_from_type('jobtypes'), 'jobtypes', 'jobtypes => jobtypes');

###############################################################################
# check_templates()

is (
  Dicop::Handler::_check_templates(
    { config => { tpl_dir =>  './', mailtxt_dir => '', } }, 'mail', 'warn', qw/testfile/),
  0, 'testfile.txt exists');

1; # EOF

