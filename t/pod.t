#!/usr/bin/perl -w

# test POD for correctness

use strict;
use Test::More;

BEGIN
   {
   chdir 't' if -d 't';
   use lib '../lib';
   eval "use Test::Pod";
   # SKIP all and exit if Test::Pod unusable
   plan skip_all => 'Test::Pod not installed on this system' if $@;
   plan tests => 23;
   };

for my $file (qw(
  Dicop/Base.pm
  Dicop/Cache.pm
  Dicop/Client/LWP.pm
  Dicop/Client/wget.pm
  Dicop/Cache.pm
  Dicop/Config.pm
  Dicop/Connect.pm
  Dicop/Event.pm
  Dicop/Handler.pm
  Dicop/Hash.pm
  Dicop/Item.pm
  Dicop/Item/Template.pm
  Dicop/Mail.pm
  Dicop/Request.pm
  Dicop/Request/Pattern.pm
  Dicop/Security.pm
  ../BUGS
  ../CHANGES
  ../CHANGES-3.00
  ../INSTALL
  ../README
  ../README.win32
  ../TODO
  ))
  {
  pod_file_ok('../lib/' . $file);
  }
