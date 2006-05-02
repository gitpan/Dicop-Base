#############################################################################
# Dicop::Mail -- send email
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Handler;
use vars qw/$VERSION $BUILD/;

use strict;
use Mail::Sendmail;
use Dicop::Event qw/crumble msg/;

sub flush_email_queue
  {
  # try to send all mails in queue, return number of items successfully sent
  my ($self,$write) = @_;
  $write ||= 0;			# for testsuite to disable writing

  my $queue = $self->{email_queue};
  return 0 if @$queue == 0;		# no mails queued

  # if mailserver is not entirely dead, it might timeout, so catch this to
  # never try to email for more than 10 seconds

  my $old_handler = $SIG{ALRM};
  my $die_msg = msg(98, 'Email connection timed out.'); $die_msg =~ s/\n//;
  $SIG{ALRM} = sub { die $die_msg; };		# die handler will log this
  my $old_alarm = alarm(10);

  my $logfile = "$self->{config}->{log_dir}/mail.log";

  $Mail::Sendmail::mailcfg{smtp} = [ 'localhost' ];	# zap relay
  my @keep;
  my $sent = 0;

  eval {
    while (@$queue)
      {
      my $msg = $queue->[0];	# first entry
      $msg->{'X-Mailer'} = "DiCoP v" . $self->version() . " build " . $self->build()
      . " (Dicop::Base v$Dicop::Base::VERSION build $Dicop::Base::BUILD)"
      . " (Mail::Sendmail v$Mail::Sendmail::VERSION)";
 
      # write mail to a file
      if (($write == 0) && ($msg->{written} == 0))
        {
        $msg->{written}++;					# only once
        open FILE, ">>$logfile" or
         crumble ("Can't write $logfile: $!") && return;
        print FILE $msg->{header},"\n";
        print FILE $msg->{message},"\n";
        close FILE;
        }
      if ($msg->{server} ne 'none')
        {
	# do really send
	my $message = { %$msg };
        delete $message->{header};	# clean a bit
        delete $message->{written};	# clean
        my $rc = sendmail (%$message);
        if (!$rc)
	  {
	  push @keep, $msg;					   # message
	  crumble ("$Mail::Sendmail::error#$Mail::Sendmail::log"); # log
          }
        else
          {
          $sent++;
          }
        } # dont send if disabled
      shift @$queue;		# remove mailed/handled
      } # for all mails in queue
    }; # end eval for all mails
  push @$queue, @keep; 		# the ones that couldn't be sent must be keept
  crumble ($@) if $@;				# timeout?
  alarm($old_alarm);				# restore alarm
  $SIG{ALRM} = $old_handler if $old_handler;	# restore handler
  $sent;
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Mail - send email

=head1 SYNOPSIS

	use Dicop::Mail;

	use base qw/Dicop::Handler/;

	...

	$self->flush_email_queue($write_flag);

=head1 REQUIRES

Mail::Sendmail, Dicop::Event

=head1 EXPORTS

Exports nothing.

=head1 DESCRIPTION

Dicop::Mail inserts a flush_email_queue into the Dicop::Handler class.

It's purpose is to separate the email sending out, so that the client
can inherit from Dicop::Handler without the need for Mail::Sendmail.

=head1 METHODS

=head2 flush_email_queue($write_flag);
  
Tries to send all mails in the queue, and return the number of mails
successfully sent. This should be called outside the code that handles a
client request, so that the client does not need to wait until all the
emails are sent.

This routine will also put all to-be-sent emails into a logfile
unless C<$write_flag> is true.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

