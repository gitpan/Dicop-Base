#############################################################################
# Dicop::Event -- error messages and event handling
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Event;
$VERSION = 1.04;	# Current version of this package
require  5.008001;	# requires this Perl version or later

use Exporter;
@ISA = qw/Exporter/;
@EXPORT_OK	= qw(lock unlock give_up crumble logger msg load_messages);
use strict;

#############################################################################

my $message = {};

my $handler = 
 sub { 
   my $txt = shift || 'Unknown error message.';
   my $log = shift || 'logs/error.log';

   logger ($log,$txt);
   my $out = "req0000 $txt";
   "$out\n";
   };

sub handler
  {
  my $h = shift;
  die ("New error handler $h is no code ref") unless ref($h) eq 'CODE';
  $handler = $h;
  }

sub crumble
  {
  die ("Error handler $handler is no code ref") unless ref($handler) eq 'CODE';
  &$handler(@_);
  }

sub give_up
  {
  die ("Error handler $handler is no code ref") unless ref($handler) eq 'CODE';
  require Carp; Carp::croak( &$handler(@_) );
  }

sub logger
  {
  # append to a logfile
  my $logfile = shift; $logfile .= '.log' unless $logfile =~ /\./;

  # untaint logfile name 
  if ($logfile !~ /^([a-zA-Z0-9:\._\/\\-]+)$/)
    {
    die ("Illegal character in '$logfile' - can't log");
    }
  $logfile = $1;
  
  my $txt = time; 
  foreach (@_)
    {
    $txt .= "#$_";
    }
  $txt =~ s/\n/ /;		# remove \n from text
  Dicop::Event::lock('dicop_log_lock');
  open my $LOGFILE, ">>", $logfile or (die "Can't append to $logfile: $!");
  print $LOGFILE $txt,"\n";
  close $LOGFILE;
  Dicop::Event::unlock('dicop_log_lock');
  }

sub lock
  {
  no strict 'refs';
  my $lf = shift || 'dicop_lockfile';
  open ("LOCKFILE_$lf" , ">$lf") || die ("cant open lockfile $lf $!");
  flock("LOCKFILE_$lf",2) or die ("can't lock $lf $!");
  }

sub unlock
  {
  my $lf = shift || 'dicop_lockfile';

  return unless -e $lf;                         # already unlocked?
  no strict 'refs';
  flock("LOCKFILE_$lf",8);
  close("LOCKFILE_$lf");
  unlink $lf;
  }

sub msg
  {
  # replace a given message number with message text, and replace
  # params, then return message
  my $msg = shift || 501;

  my $m;
  if (!defined $message->{$msg})
    {
    $m = "502 No error message for error #$msg";
    }
  else
    {
    my $code = $msg;
    $code = '0' . $code while length($code) < 3;	# 90 => 090
    $m = "$code $message->{$msg}";
    $m =~ s/##time##/scalar localtime/eg;
    my $i = 1;
    foreach my $t (@_)
      {
      my $s = $t; $s = '' unless defined $s;
      $m =~ s/##param$i##/$s/g; $i++;
      }
    }
  return $m || "502 No error message for #$msg";
  }

sub load_messages
  {
  my $file = shift;
  my $log = shift;

  open my $MSGFILE, "<", $file or crumble ("Can not read $file: $!",$log) and return;
  local $/ = "\n";	# v5.6.0 seems to destroy this sometimes
  while (<$MSGFILE>)
    {
    next if /^\s*(#|$)/;	# skip comments and empty lines
    crumble ('Invalid line in message file $file',$log)
     unless /([0-9]{3}) (.*)$/;
    my $code = $1||0; my $msg = $2 || '';
    $code =~ s/^0+//;			# strip leading zeros
    $msg =~ s/\s+$//;			# strip trailing spaces
    $message->{$code} = $msg;
    }
  close $MSGFILE;
  1;					# okay
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Event - handle error messages in a Dicop system

=head1 SYNOPSIS

	use Dicop::Event qw/crumble/;

	crumble ('Help!');
	crumble ('Error 404',404);

	Dicop::Error::handler ( \&my_handler );

	crumble ('You <B>fail!</B> ;o)');	# display for browser

	logger ('logs/server.log','Error','405','No data found.');

	sub my_handler
          {
	  my $txt = shift || 'Unknown error';
	  my $code = shift || 0;
          log ($code,$txt);
	  print "Content-type: text/html\n\n");
	  print "$code: " if definded $code; 
          print "$txt\n";
          }

=head1 REQUIRES

perl5.008001, Exporter

=head1 EXPORTS

Exports C<crumble>, C<msg>, C<load_messages> and C<logger> on demand.

=head1 DESCRIPTION

This module exports on demand crumble and event. Use C<crumble()> instead of
die() to pass the error message back to the client and log the error.

=head1 METHODS

=head2 crumble

Given an error message, this routine displays the message on the screen.
All errors are logged to a file, too.

You can set your own error handler via C<Dicop::Error::handler>.

=head2 give_up

Just like L<crumble>, but dies afterwars.

=head2 logger

Log all given args in one line to logfile. First arg is dir and name of
logfile.

=head2 load_messages

Load the messages from disk from the given filename.

=head2 msg

	print msg(100,'foo');	# 'you said ##param1##' becomes 'you said foo'

Return a message for a given message number, and inline any given parameter
into the message text.

=head2 handler

Set/get error handler.

=head2 lock

Given a filename, create a lock on that filename and wait on it until it is
free. Used to ensure that only one server object (or thread) accesses the
data at a time, to ensure data consistency and integry.

The filename defaults to 'dicop_lockfile'.

This routine is automatically called upon creation of a Dicop::Data object.
L<unlock> is used to release the lock upon DESTROY of the object.

=head2 unlock

Given a filename, remove a potential lock on that file. See also L<lock>.

=head1 BUGS

None known yet.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

