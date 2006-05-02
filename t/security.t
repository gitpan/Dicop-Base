#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  plan tests => 319;
  chdir 't' if -d 't';
  }

use Dicop::Security qw/
  valid_net valid_ip
  hash_pwd
  ip_matches
  ip_is_in_net
  ip_is_in_net_list
  /;
use Dicop::Request;

use Dicop::Event;
Dicop::Event::load_messages("msg/messages.txt") or die();

###############################################################################
# ip and net checking/matching

is (valid_net('1.2.3.4/32'),1);
is (valid_net('1.2.3.0/24'),1);
is (valid_net('1.2.0.0/16'),1);
is (valid_net('1.0.0.0/8'),1);
is (valid_net('1.2.3.4/0'),0); 	# only 0.0.0.0/0 is valid
is (valid_net('0.0.0.0/0'),1);
is (valid_net('1.2.3.4'),1);	# special case, IP is a (very restricted) net
is (valid_net('1.2.3.4/'),0);
is (valid_net('1.2.3.4/1'),0);

is (valid_net('any'),1);
is (valid_net('none'),1);

is (valid_ip(undef),0);
is (valid_ip('1.2.3.4'),1);
is (valid_ip('256.2.3.4'),0);
is (valid_ip('256.256.3.4'),0);
is (valid_ip('256.256.356.456'),0);
is (valid_ip('2.256.3.4'),0);
is (valid_ip('1.2.256.3'),0);
is (valid_ip('1.2.3.256'),0);
is (valid_ip('1.2.0.4'),1);
is (valid_ip('0.0.0.0'),1);
is (valid_ip('255.255.255.255'),1);
is (valid_ip('1.2.0.-4'),0);
is (valid_ip('1.2.0'),0);

is (valid_ip('none'),0);			# only as net, not as IP
is (valid_ip('any'),0);				# only as net, not as IP

is (ip_is_in_net('1.2.3.4','1.2.3.4'),1);	# valid net
is (ip_is_in_net('1.2.3.4','1.2.3.4/'),-2);	# invalid net
is (ip_is_in_net('-1.2.3.4','1.0.0.0/8'),-1);	# invalid ip
is (ip_is_in_net('-1.2.3.4','1.2.3.4/7'),-1);	# both, invalid ip

is (ip_is_in_net('1.2.3.4','1.2.3.4/32'),1);
is (ip_is_in_net('1.2.3.4','1.2.3.0/24'),1);
is (ip_is_in_net('1.2.3.4','1.2.0.0/16'),1);
is (ip_is_in_net('1.2.3.4','1.0.0.0/8'),1);
is (ip_is_in_net('1.2.3.4','0.0.0.0/0'),1);

my $r1 = rand(255)+1; my $r2 = rand(255)+1;
my $r3 = rand(255)+1; my $r4 = rand(255)+1;
for (my $i = 0; $i < 256; $i++)
  {
  my $ok = 0;
  $ok++ unless ip_is_in_net("$r1.$r2.$r3.$i","$r1.$r2.$r3.$i/32");
  $ok++ unless ip_is_in_net("$r1.$r2.$r3.$i",'$r1.$r2.$r3.0/24');
  for (my $j = 0; $j < 256; $j++)
    {
    $ok ++ unless ip_is_in_net("$r1.$r2.$j.$i",'$r1.$r2.0.0/16');
# takes too long:
#    for (my $k = 0; $k < 256; $k++)
#      {
#      $ok ++ unless ip_is_in_net("$r1.$k.$j.$i",'$r1.0.0.0/8');
#      }
    }
  is ($ok,0);
  }

my $nets = [ '1.2.3.0/24', '2.3.4.5/32', '3.4.0.0/16', '4.0.0.0/16' ];

foreach my $ip ('1.2.3.4', '2.3.4.5', '3.4.1.2', '4.0.1.2')
  {
  my $rc = ip_is_in_net_list($ip,$nets);
  is ($rc,1);
  }

foreach my $ip ( '2.3.4.6' )
  {
  my $rc = ip_is_in_net_list($ip,$nets);
  is ($rc,0);
  }

###############################################################################
# ip matching with sub-net masks

# normal check with /8 subnet
is (ip_matches ('1.2.3.4', '1.2.3.0', '255.255.255.0'), 1);
is (ip_matches ('1.2.3.5', '1.2.3.0', '255.255.255.0'), 1);
is (ip_matches ('1.2.4.4', '1.2.3.0', '255.255.255.0'), 0);
is (ip_matches ('1.3.3.4', '1.2.3.0', '255.255.255.0'), 0);
is (ip_matches ('2.2.3.4', '1.2.3.0', '255.255.255.0'), 0);
is (ip_matches ('1.2.3.0', '1.2.3.0', '255.255.255.0'), 1);

is (ip_matches ('128.254.13.0', '128.254.13.0', '255.255.255.0'), 1);

# dito, but the check IP has a superflous part
is (ip_matches ('1.2.3.4', '1.2.3.5', '255.255.255.0'), 1);
is (ip_matches ('1.2.3.5', '1.2.3.5', '255.255.255.0'), 1);
is (ip_matches ('1.2.4.4', '1.2.3.5', '255.255.255.0'), 0);
is (ip_matches ('1.3.3.4', '1.2.3.5', '255.255.255.0'), 0);
is (ip_matches ('2.2.3.4', '1.2.3.5', '255.255.255.0'), 0);
is (ip_matches ('1.2.3.0', '1.2.3.5', '255.255.255.0'), 1);

# strict check
is (ip_matches ('1.2.3.4', '1.2.3.4', '255.255.255.255'), 1);
is (ip_matches ('1.2.3.5', '1.2.3.4', '255.255.255.255'), 0);
is (ip_matches ('1.3.3.4', '1.2.3.4', '255.255.255.255'), 0);
is (ip_matches ('2.2.3.4', '1.2.3.4', '255.255.255.255'), 0);
is (ip_matches ('2.1.8.4', '1.2.3.4', '255.255.255.255'), 0);

is (ip_matches ('128.1.18.4', '128.1.18.4', '255.255.255.255'), 1);

is (ip_matches ('128.254.18.4', '128.254.0.0', '255.255.0.0'), 1);
is (ip_matches ('128.254.0.0', '128.254.0.0', '255.255.0.0'), 1);

###############################################################################
# hash_pwd and valid_user

is (hash_pwd('Test'),'0cbc6611f5540bd0809a388dc95a615b');
is (hash_pwd("OneRingMyPrecious\n"),'67bec90bb676ab497383be1759521b64');

1;

