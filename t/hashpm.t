#!/usr/bin/perl -w

use Test::More;
use strict;

BEGIN
  {
  unshift @INC, '../lib';
  chdir 't' if -d 't';
  plan tests => 22;
  use_ok qw/Dicop::Hash/;
  }

can_ok ('Dicop::Hash', qw/error as_hex update compare/);

open (FILE, '>hash.txt');
print FILE 'ABCDEFGHIJKLMNOPQRSTUVWXYZ\n';
close FILE;

my $time = time;
my $hash = Dicop::Hash->new ( 'hash.txt' );

my $t = $time - $hash->{_modified};
if ($t < 3)			# should take no more than 3 seconds!
  {
  is (1,1, 'skipped');
  }
else
  {
  is ('$t < 3', $t, 't < 3');
  }
is ($hash->as_hex(),'3c9dd79e8de5b0c5e713b6724c7676b9', 'hash is right');

#############################################################################
# hashing of scalars and compare

my $hash2 = Dicop::Hash->new ( \'ABCDEFGHIJKLMNOPQRSTUVWXYZ\n' );
is ($hash2->error(), '', 'no error');
is ($hash2->as_hex(),'3c9dd79e8de5b0c5e713b6724c7676b9', 'hash is right');

is ($hash->compare($hash2), 1, 'cmp ok');
is ($hash2->compare($hash2), 1, 'cmp ok');
is ($hash->compare($hash), 1, 'cmp ok');
is ($hash2->compare($hash), 1, 'cmp ok');

#############################################################################
# check update

sleep(1);
open (FILE, '>hash.txt');
print FILE 'ABCDEFGHIJKLMNOPQRSTUVWXYZ\nABCDEFGHIJKLMNOPQRSTUVWXYZ';
close FILE;

$hash->update();
$t = $time - $hash->{_modified};
if ($t < 3)			# should take no more than 3 seconds!
  {
  is (1,1, 'skipped');
  }
else
  {
  is ('$t < 3',$t, 't < 3');
  }
is ($hash->as_hex(),'e93b062536ff2007dba1e0e84c49d17a', 'hash is right');

is ($hash->compare($hash2), '', 'cmp nok');
is ($hash2->compare($hash2), 1, 'cmp ok');
is ($hash->compare($hash), 1, 'cmp ok');
is ($hash2->compare($hash), '', 'cmp nok');

# modify file, but trick Hash.pm into thinking timestamp did not change (which
# it probably didn't but play safe with second-leap)
truncate('hash.txt',1);
$hash->{_modified} = [ stat('hash.txt') ]->[9];

# hash changes since size changes
is ($hash->as_hex(),'7fc56270e7a70fa81a5935b72eacbe29', 'hash is right');

unlink 'hash.txt';

#############################################################################
# test with non-existing file

$hash = Dicop::Hash->new ( 'hash.txt' );
is (ref($hash->as_hex()), 'SCALAR', 'error');
my $error = $hash->as_hex();
like ($$error, qr/Cannot hash.*hash.txt.*[nN]o such file/,
  'no such file');

#############################################################################
# simulate internal error that shouldn't happen (tries to rehash)

$hash->{_hash} = '';
$hash->{_error} = '';
is (ref($hash->as_hex()), 'SCALAR', 'unknown error');
$error = $hash->as_hex();
like ($$error, qr/Cannot hash.*hash.txt.*[nN]o such file/,
  'no such file');

# create hash.txt:

open FILE, ">hash.txt" or die ("Cannot create hash.txt: $!");
print FILE "ABCDEEFG";
close FILE;

my $h = $hash->as_hex();
is ($h, "79baa88613c4829a7772aac886ae5dc3", 'hash.txt hashed');

END { unlink 'hash.txt'; }
