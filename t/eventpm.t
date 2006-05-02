#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 8;
  }

use Dicop::Event qw/lock unlock msg load_messages logger/;

is (msg(90,'foo'), '502 No error message for error #90');
load_messages('msg/messages.txt');
is (msg(90,'foo'), "090 Cannot find worker foo");

eval "Dicop::Event::handler('test');";
like ($@, qr/^New error handler test is no code ref/, 'error condition set');

my $h = Dicop::Event::handler( sub { 8 });
is (ref($h), 'CODE', 'handler is code ref'); 

# test logging

#logger('/dev/null', "test");

###############################################################################
# file locking

# try locking with default name
my $lock = 'dicop_lockfile';
if (-e $lock)
  {
  unlink $lock;
  die "Can not remove lockfile $lock: $!" if -e $lock;
  }
lock();			# lock dicop_lockfile

print "# $!\n" unless
  is (-e $lock, 1, "Lockfile $lock was created");

unlock();		# unlock dicop_lockfile
print "# $!\n" unless
  is (!-e $lock, 1, "Lockfile $lock was removed");

# custom lock file name
$lock = 'dicop_request_lockfile';
if (-e $lock)
  {
  unlink $lock;
  die "Can not remove lockfile $lock: $!" if -e $lock;
  }
lock($lock);

print "# $!\n" unless
  is (-e $lock, 1, "Lockfile $lock was created");

unlock($lock);
print "# $!\n" unless
  is (!-e $lock, 1, "Lockfile $lock was removed");

1; # EOF

