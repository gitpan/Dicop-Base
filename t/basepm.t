#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  plan tests => 565;
  chdir 't' if -d 't';
  }

use Dicop::Request;
use Math::BigInt;
use Math::BigFloat;
use Dicop::Base qw/
		h2a a2h
		ago simple_ago encode decode parseFormArgs
		replace_templates
		cfg_level cfg_default
		cpuinfo
  /;

is ($Dicop::Base::BUILD ne '', 1 , 'BUILD defined');

can_ok ('Dicop::Base', qw/read_file read_dir read_list h2a a2h ago simple_ago
			  decode encode parseFormArgs
			/);

###############################################################################
# test parameter parsing

my $form = "req0000=client_foo;id_55;job_44"
          ."\&req0001=client_foo;id_15;job_14"
          ."\&req00005=client_blar;id_35;speed_1,2,3";

$form = parseFormArgs($form);
my @requests;
foreach my $r (sort keys %$form)
  {
  next unless $r =~ /^req[0-9]{4}$/; # ignore anything else
  push @requests,
    Dicop::Request->new ( id => $r, data => $form->{$r} );
  }
   
is (scalar @requests, 2, '2 requests');

is ($requests[0]->{client},'foo', 'client is foo');

###############################################################################
# test parameter parsing with empty params

$form = parseFormArgs("foo=something&me=&=bam");

is (scalar keys %$form, 2, 'foo=something & me=');
is ($form->{foo}, 'something', 'foo=something');
is ($form->{me}, '', "me=''");

###############################################################################
# ago

is (ago(23),'23 seconds');
is (ago(1),'1 second');
is (ago(81),'1 minute and 21 seconds (81s)');
is (ago(3600+120+12),'1 hour, 2 minutes and 12 seconds (3732s)');
is (ago(3600+60+1),'1 hour, 1 minute and 1 second (3661s)');
is (ago(24*3600+7200+240+2),'1 day, 2 hours, 4 minutes and 2 seconds (93842s)');
is (ago(2358120000),'27293 days, 1 hour and 20 minutes (2358120000s)');
is (ago(3620),'1 hour and 20 seconds (3620s)');
is (ago(24*3600+32),'1 day and 32 seconds (86432s)');
is (ago(24*3600+120),'1 day and 2 minutes (86520s)');
is (ago(21.765),'21 seconds');				# make int
is (ago(0),'0 seconds');	

# with BigInt/BigFloat
is (ago(Math::BigInt->new(0)),'0 seconds');	
is (ago(Math::BigFloat->new(0)),'0 seconds');	
is (ago(Math::BigInt->new(2)),'2 seconds');	
is (ago(Math::BigFloat->new(2)),'2 seconds');	

# simple_ago
is (simple_ago(32),'32 seconds');
is (simple_ago(1),'1 second');
is (simple_ago(180),'3 minutes (180s)');
is (simple_ago(3600+120+30),'62.5 minutes (3750s)');
is (simple_ago(3600+60+1),'61 minutes (3661s)');
is (simple_ago(24*3600+7200+240+2),'26 hours (93842s)');
is (simple_ago(24*3600*2+24*3600),'3 days (259200s)');
is (simple_ago(21.765),'21 seconds');			# make int
is (simple_ago(0),'0 seconds');	

# with BigInt/BigFloat
is (simple_ago(Math::BigInt->new(0)),'0 seconds');	
is (simple_ago(Math::BigFloat->new(0)),'0 seconds');	
is (simple_ago(Math::BigInt->new(2)),'2 seconds');	
is (simple_ago(Math::BigFloat->new(2)),'2 seconds');	

# cache_time, time
my $t = Dicop::Base::cache_time();
is ($t,Dicop::Base::time(), 'time cached');
sleep(2);
is ($t,Dicop::Base::time(), 'still cached');					# still the same?

$t = Dicop::Base::read_file('testfile.txt');
is (ref($t),'SCALAR');
is ($$t,"All your test are belong to us.\n");

# decode and encode
is (encode(' '),'+');
is (encode('+'),'%2b');
is (encode('123'),'123');		# digits are not encoded!
is (encode('%'),sprintf("%%%02x",ord('%')));
is (encode("\n"),'%0a');
is (encode("\x0a\x0d"),'%0a%0d');

print "# for 0 .. 255 { decode(encode(\$char)) eq \$char }\n";

my $ok = 0;
for (0..255)
  {
  my $char = sprintf("%c",$_);
  if (decode(encode($char)) eq $char)
    {
    $ok++;
    }
  else
    {
    print "# not ok $_ ('$char'), got '", decode(encode($char)),
      "'\n";
    }
  }

is ($ok, 256, 'all 256 tests passed');

###############################################################################
# h2a a2h

for (my $i = 0; $i < 255; $i++)
  {
  my $hex = sprintf ('%02x',$i);
  print "# Tried a2h(h2a('$hex')) eq '$hex'\n" unless
  is ( a2h(h2a( "$hex" )), $hex );
  print "# Tried a2h(h2a('$hex$hex')) eq '$hex$hex'\n" unless
  is ( a2h(h2a( "$hex$hex" )), "$hex$hex" );
  }

###############################################################################
# read_dir

my $files = Dicop::Base::read_dir("test-dir");

is (scalar @$files, 4, '. .. foo bar');
is (join(":", sort @$files), '.:..:bar:foo', "all files/dir found");

###############################################################################
# cfg_level

my $cfg = { log_level => "1+2+4", log_test => "2+4", debug_level => "2+4+8", };

Dicop::Base::cfg_level($cfg, qw/log_level log_test/);

is (scalar keys %$cfg, 3, '3 keys');
is ($cfg->{log_level}, 7, 'log_level');
is ($cfg->{log_test}, 6, 'log_test');
is ($cfg->{debug_level}, "2+4+8", 'debug_level');

###############################################################################
# read_table_template()

my ($txt, $tpl) = Dicop::Base::read_table_template( 'tpl/editfield_select.inc' );

like ($$txt, qr/##table##/, 'template got replaced');
like ($tpl, qr/<option name="##fieldname##" value="##validvalue##">##validname##/, 'template found');

