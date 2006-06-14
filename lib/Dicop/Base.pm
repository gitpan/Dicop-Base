#############################################################################
# Dicop::Base -- base for a Dicop HTTP server
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Base;
use vars qw($VERSION $BUILD @ISA @EXPORT_OK);
use strict;

$VERSION = '3.04';	# Current version of this package
$BUILD = 0;		# Current build of this package
require 5.008001;	# requires this Perl version or later

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(
		parseFormArgs
                read_list write_list read_file write_file read_dir
		a2h h2a replace_templates
		time cache_time ago simple_ago
		status status_code
		random
		encode decode
		cfg_default cfg_level
		cpuinfo
                );
use Dicop::Event qw/crumble msg/;
use File::Spec;

sub read_list
  {
  my $file = shift;
  
  my $list = []; my $line;
  open DICOP_HANDLE, $file or return crumble ("Can't read $file: $!");
  while (my $line = <DICOP_HANDLE>)
    {
    next if $line =~ /^\s*#/;	# skip comments
    next if $line =~ /^\s*$/;	# skip empty lines
    push @$list, $line;
    }
  close DICOP_HANDLE or return crumble("Can't close $file: $!");
  $list;
  }

sub read_file
  {
  my $file = shift;
  
  my $txt = "";
  open (DICOP_HANDLE, "$file") or return crumble ("Can't read '$file': $!");
  local $/ = "";	# slurp mode
  while (my $line = <DICOP_HANDLE>)
    {
    $txt .= $line;
    }
  close DICOP_HANDLE or return crumble("Can't close '$file': $!");
  \$txt;
  }

sub read_dir
  {
  my $dir = shift;
  
  opendir (DICOP_HANDLE, "$dir") or return crumble ("Can't read dir '$dir': $!");
  my @files = readdir (DICOP_HANDLE);
  closedir DICOP_HANDLE or return crumble("Can't close dir '$dir': $!");
  \@files;
  }

sub write_file
  {
  my $file = shift;

  return crumble ("Filename is undef") if !defined $file;
  return crumble ("Filename is empty") if $file eq '';
  return crumble ("Filename contains '..'") if $file =~ /\.\./;

  my $txt = shift || return crumble ("Can't write empty text to '$file'!");

  # generate the dir if it doesn't already exist
  my ($vol,$dir,$f) = File::Spec->splitpath($file);
  my @dirs = File::Spec->splitdir($dir);

  my $combined = '.';
  foreach my $d (@dirs)
    {
    $combined = File::Spec->catdir($combined,$d);
    if (!-d $combined)
      {
      print STDERR "Creating directory $combined\n";
      return crumble ("Couldn't create dir $combined: $!") unless 
        mkdir $combined, 0750;
      }
    }
  
  open DICOP_HANDLE, ">$file" or return crumble ("Can't write '$file': $!");
  binmode DICOP_HANDLE;
  print DICOP_HANDLE $$txt;
  close DICOP_HANDLE or return crumble("Can't close '$file': $!");

  return;
  }

sub read_table_template
  {
  # read a file containing a table template, which contains a table and
  # one row of the table (or anything else) between <!-- start --> and
  # <!-- end -->. Returns reference to empty table with ##table## inserted
  # at the place of the template, and the template for one row.

  my $file = shift;

  my $txt = read_file($file);
  die ($txt||"Can't read file $file: $!") unless ref $txt;

  $$txt =~ s/<!-- start -->\n?((.|\n)+)\n?<!-- end -->/##table##/i;
  my $tpl = ($1 || '') . "\n";
  ($txt,$tpl);
  }

# convert "ab" to "6566"
sub a2h
  {
  use bytes;
  my ($a) = shift;
  return '' if !defined $a || $a eq '';		# not defined or empty?
  unpack ( "H" . (length($a) << 1), $a);
  }

# convert "6566" to "ab"
sub h2a
  {
  use bytes;
  my ($h) = shift;
  return '' if !defined $h || $h eq '';		# not defined or empty?
  pack ("H" . length($h), $h);
  }

sub simple_ago
  {
  # from a given time difference, create a string reporting it in
  # seconds/mins/hours/days as appropriate
 
  my ($t) = @_;
  $t = 0 if !defined $t or (!ref $t && $t eq '');
  $t = int($t);						# make int
  $t = $t->numify() if ref($t);				# to scalar
  my $s = " ($t"."s)";
  if ($t < 120)
    {
    my $h = "$t second"; $h .= 's' if $t != 1; $t = $h;
    $s = "";
    }
  elsif ($t < 2*3600)
    {
    $t = int($t/6)/10; $t = "$t minutes";
    }
  elsif ($t < 2*3600*24)
    {
    $t = int($t/(360))/10; $t = "$t hours";
    }
  else
    {
    $t = int($t/(360*24))/10; $t = "$t days";
    }
  "$t$s";
  }

sub ago
  {
  # from a given amount of time in seconds, create a string reporting it in
  # seconds/mins/hours/days as appropriate

  my ($t) = @_; 
  $t = 0 if !defined $t or (!ref $t && $t eq '');
  $t = int($t);						# make int
  $t = $t->numify() if ref($t);				# to scalar
  my $s = $t;
  my $seconds = $t % 60; 
  $t = int($t / 60); my $minutes = $t % 60;
  $t = int($t / 60); my $hours = $t % 24;
  $t = int($t / 24); my $days = $t;
  my $sec = 'second'; $sec .= 's' if $seconds != 1; 
  my $hr = 'hour'; $hr .= 's' if $hours > 1; 
  my $min = 'minute'; $min .= 's' if $minutes > 1; 
  my $d = 'day'; $d .= 's' if $days > 1; 
  return "$s $sec" if ($minutes+$days+$hours == 0);
  my @items = ();
  push @items, "$days $d" if $days > 0;
  push @items, "$hours $hr" if $hours > 0;
#   if $hours > 0 && ($days > 0 || $minutes > 0 || $seconds > 0);
  push @items, "$minutes $min" if $minutes > 0;
#   if $minutes > 0 && ($seconds > 0 || $hours > 0 || $days > 0);
  push @items, "$seconds $sec" if $seconds > 0;
#   if $seconds > 0 && ($minutes > 0 || $hours > 0 || $days > 0);
  # join with ',' , but last with 'and'
  my $es = join (', ',@items);
  $es =~ s/(.*),/$1 and/;			# last , => and
  $es." ($s".'s)';
  }

sub replace_templates
  {
  # take a ref to a text template and a hash containing keys, and replace
  # occurances of ##key## in the text with the value
  my ($txt,$hash) = @_;

  if (!ref ($txt))
    {
    require Carp;
    Carp::cluck ("Need ref to scalar, got " . ref($txt));
    }
  # replace ##key## with the value of the key
  my $val;
  if (ref($hash) eq 'HASH' || !$hash->can('fields'))
    {
    foreach my $key (sort keys %$hash)
      {
      $val = $hash->{$key};
      $val = "undefined value for key $key" if !defined $val;
      $$txt =~ s/##$key##/$val/g;
      }
    }
  else
    {
    # if we got an object, ask it for its fields that we must use as keys
    foreach my $key ($hash->fields())
      {
      $val = $hash->get_as_string($key);
      $val = "undefined value for key $key" if !defined $val;
      $$txt =~ s/##$key##/$val/g;
      }
    }

  $txt;
  }

########################################################
# fetch client arguments and return them

sub parseFormArgs
  {
  # inspired by Michael Budash
  my ($name,$value,%form,@pairs);

  my $incoming;
  if (($ENV{'REQUEST_METHOD'}||"") eq "POST")
    {
    read(STDIN, $incoming, $ENV{'CONTENT_LENGTH'} || 0);
    }
  else
    {
    $incoming = $ENV{'QUERY_STRING'} || $_[0] || '';
    }
  @pairs = split(/&/, $incoming);

  # protect against "Algorithmn Complexity Attack against Perl hash function"
  if (scalar @pairs > 1024)
    {
    die ("Error: More than 1024 arguments.");
    return \%form;
    }

  use bytes;
  foreach (@pairs) 
    {
    ($name, $value) = split(/=/, $_);

    # skip blank names (but keep blank values)
    next if !defined $name || $name eq '';

    # Un-Webify plus signs and %-encoding
    $name  =~ tr/+/ /;
    $value = '' unless defined $value;
    $value =~ tr/+/ /;
    $name  =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/ge;
    $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/ge;

    $form{$name} = $value;
    }
  \%form;
  }

sub encode
  {
  # encode a string that contains characters other than A-Z,a-z,0-9 etc
  use bytes;
  my $var = "$_[0]";

  # encode % as %25 first
  $var =~ s/%/sprintf ("%%%02x",ord("%"));/eg;
  # encode other critical characters
  $var =~ s/([^A-Za-z0-9\.\/\\,%:\s-]|\n|\r)/sprintf("%%%02x",ord($1));/eg;
  # encode ' ' as '+'
  $var =~ tr/ /+/;
  $var;
  }

sub decode
  {
  # decode a string containing + (space) and %XX (hex)
  use bytes;
  my $var = shift; $var = '' unless defined $var;

  $var =~ tr/+/ /;
  $var =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/ge;
  $var;
  }

sub cfg_level
  {
  my $cfg = shift;
  
  foreach my $k (@_)
    {
    my $l = [ split (/\s*[\+]\s*/, ($cfg->{$k}||0)) ]; my $sum = 0;
    foreach (@$l)
      {
      $sum += $_;
      }
    $cfg->{$k} = $sum;
    }
  }

sub cfg_default
  {
  # given a set of keys and their values (a list or hash reference),
  # sets these values as default in the internal cfg object, unless
  # the key is already defined there.
  my $self = shift;

  my $args;
  ref $_[0] ? $args = shift : $args = { @_ };
  foreach (keys %$args)
    {
    $self->{config}->{$_} = $args->{$_} if !defined $self->{config}->{$_};
    }
  $self;
  }

{
  # protected vars
  my $rand_buffer = '';
  my $time = CORE::time;

  sub random
    {
    # return $bits random bits (rounded down to the nearest multiple of 8)
    # Uses /dev/urandom, or if this is not available, chains calls to rand()
    # (The latter is not as secure, but the way it was before we used
    # /dev/urandom)
    my $chars = int((shift || 128) / 8);

    if (length($rand_buffer) <= $chars)
      {
      # rand_buffer not long enough, refill it
      my $dev;
      my $rc = open ($dev, '/dev/urandom');
      if ($rc)
        {
        while (length($rand_buffer) <= $chars)
	  {
	  read ($dev,$rand_buffer, 4096);
	  }
        close $dev;
        }
      else
        {
        while (length($rand_buffer) < 4096)
          {
          $rand_buffer .= int(rand(65537));
          }
        }
      }
    my $buffer = substr($rand_buffer,0,$chars);	# get some bytes
    substr($rand_buffer,0,$chars) = '';		# and remove from rand_buffer
    $buffer;
    }

  sub time
    {
    $time;
    }

  sub cache_time
    {
    $time = CORE::time;
    }
}

sub cpuinfo
  {
  my ($self,$no_warn) = @_;

  # try to get info on cpu
  my $cpuinfo = "";
  if ($^O !~ /win32/i)
    {
    eval { require Linux::Cpuinfo; };
    if (defined $Linux::Cpuinfo::VERSION)
      {
      my $cpu = Linux::Cpuinfo->new( { NoFatal => 1 } );
      if (ref($cpu))
        {
        $cpuinfo  = $cpu->model_name() || 'unknown';
        $cpuinfo =~ s/[_=;,]/-/g;			# no underscores etc
        $cpuinfo =~ s/[\[\(](tm|r)[\)\]]//gi;		# don't need this
        $cpuinfo =~ s/\s+/ /g;				# '  ' => ' '
        $cpuinfo .= ",".int($cpu->cpu_mhz()||0);	# only in integer Hz
	$cpuinfo = ";cpuinfo_$cpuinfo";
        }
      }
    else
      {
      # warn about missing Cpuinfo
      if (!$no_warn)
        {
        no strict 'refs';
        &{ref($self).'::output'} ($self, msg(606)."\n\n");
        sleep(5);
        }
      }
    }
  else
    {
    require Win32;
    Win32->import();
    $cpuinfo = Win32::GetChipName();
    $cpuinfo =~ s/[_=;,]/-/g;			# no underscores etc
    $cpuinfo =~ s/[\[\(](tm|r)[\)\]]//gi;	# don't need this
    $cpuinfo =~ s/\s+/ /g;			# '  ' => ' '
    $cpuinfo = ";cpuinfo_$cpuinfo,0";		# unknown Mhz
    }
  $cpuinfo;
  }

1;

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Base - basics for a Dicop HTTP server/client

=head1 SYNOPSIS

	use Dicop::Base;

=head1 REQUIRES

perl5.008, Exporter

=head1 EXPORTS

Exports nothing on default.

=head1 DESCRIPTION

This is a base package that contains everything neccessary to have an HTTP
server bind to a port, running under a specific user/group and answering
L<Dicop::Requests>.

Also contains an assortment of often used or handy support routines used by
the server/proxy and the client.

=head1 METHODS

=head2 cfg_default

	Dicop::Base::cfg_default ( $self, $hash );

Given a set of keys and their values (a list or hash reference),
sets these values as default in the internal cfg object (stored in C<config>),
unless the key is already defined there.

=head2 cfg_level

	Dicop::Base::cfg_level ( $cfg, qw/log_level debug_level .../ );

Given a cfg hash and a set of keys, will convert the keys from a format like
C<1+2+32> to the sum of the elements. Works good for bitfields given as a
sum of C<2 ** X> numbers.

=head2 encode

Encode a string that contains characters other than A-Z,a-z,0-9 etc with %XX
formats (or '+' instead of spaces).

=head2 decode

	my $decoded = decode($encoded);

Decode a string containing + (space) and %XX (hex) as produced by L<encode()>.

=head2 cache_time

Use time() to get the current time and cache this value.

=head2 time

	my $time = Dicop::time();

Return the time cached by cache_time(). Subsequent calls to C<time>
will result in the same time, unless you call C<Dicop::cache_time()>
again.

=head2 a2h

Convert "ab" to "6566".

=head2 h2a

Convert "656667" to "abc".

=head2 parseFormArgs

This parses the formular data the browser/client/user send us (either by
using GET, POST, or an supplied string) and breaks it into parameters. Returns
a hash which keys are the parameters, and the values the corrosponding data.

=head2 read_file

Read a text file (given as complete path/name) and return a reference to the
data read.

=head2 write_file

	write_file( $path_to_file, \$contents);

Given a filename (with path), and a reference to a scalar,
write C<$contents> to C<$path_to_file>. If the directories do not exist,
the routine attempts to create them before writing the file.

=head2 read_list

Read a text file with lists (given as complete path/name) and return areference to the data read.

=head2 read_dir()

	my @files = Dicop::Base::read_dir($directory);

Return a list of all files and directories in the given directory.

=head2 read_table_template
  
Reads a file containing a table template, which contains a table and
one row of the table between <T> and </TR>. Returns reference to 
empty table with ##table## at the place of the template, and the
template for one row.

The following template:

	<TABLE>

	<TR>
        <TD>##field##<TD>##description##
        </TR>
        
        </TABLE>

would result in the template-text of:

	<TABLE>

	##table##
        
        </TABLE>

and the template for one row:

	<TR>
        <TD>##field##<TD>##description##
        </TR>

From this you can then create tables with more than one row.

=head2 replace_templates

Take a ref to a text template and a hash containing keys, and replace
occurances of ##key## in the text with the value.

=head2 ago

From a given amount of time in seconds, creates a string reporting it in
seconds/mins/hours/days as appropriate.

=head2 simple_ago
  
From a given time difference, create a string reporting it in
seconds/mins/hours/days as appropriate. Unlike L<ago()>, it only reports
one piece of time like "1 day", or "3 hours".

=head2 random

	$random_bytes = Dicop::random(128);	# get 128 random bytes

Returns X pseudo-random bytes. These are taken either from C</dev/urandom>
or from chained calles to rand() if C</dev/urandom> is not available or
could not be used. 

=head2 cpuinfo

	$cpuinfo = Dicop::Base::cpuinfo($self, $no_warn);

Gather cpu info like model, speed etc and return as string suitable for
sending to server.

=head1 BUGS

None known yet.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See the file LICENSE or L<http://www.bsi.de/> for more information.

=cut
