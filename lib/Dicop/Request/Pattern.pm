#############################################################################
# Dicop::Request::Pattern -- an object containing a valid request pattern
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Request::Pattern;
use vars qw($VERSION);
$VERSION = 0.04;	# Current version of this package
require  5.008;		# requires this Perl version or later

use Dicop::Item;
@ISA = qw/Dicop::Item/;
use strict;
use vars qw($VALID);

use Dicop::Base qw/encode decode/;
use Dicop::Event qw/msg/;

#############################################################################
# private, initialize self 

sub _init
  {
  my ($self,$args) = @_;

  $self->SUPER::_init($args,$self);
  $self->SUPER::_default( {
    title => 'Default pattern',
    match => '',
    opt => 'style',
    req => '',
    nonempty => '',
    throw => '',
    type => 'status',
    class => 'admin',
    output => 'html',
    tpl => '',
    auth => 1,
    tpl => '',
    sort => 'up',
    sort_by => 'id',
    carry => '',
    }, $self );

  $self->{_error} = '';

  $self;
  }

sub match
  {
  # check a given request against ourself. Return undef if ok, otherwise
  # error message.
  my ($self, $request) = @_;
 
  my $required = {}; 

  # check that the request matches this pattern, if not return (undef,undef)
  foreach my $field (@{$self->{matches}})
    {
    my ($k,$v) = @$field;
    $required->{$k} = 1;			# matching fields are required
    if (! (exists $request->{$k} && defined $request->{$k}) )
      {
      return (undef,undef);			# no match
      }
    # if exists and is defined, does it match?
    my $m;
    if ($v =~ /^\//)
      {
      # 'type_/^(foo|bar)'
      my $r = substr($v,1,length($v)-1);
      $m = $request->{$k} =~ /$r/;
      }
    else
      {
      $m = $request->{$k} eq $v;
      }
    return (undef,undef) unless $m;		# no match
    }
  
  # XXX TODO: check optional fields
 
  foreach my $k (@{$self->{nonempty}})
    { 
    $required->{$k} = 1;
    } 
  foreach my $k (@{$self->{req}})
    { 
    $required->{$k} = 1;
    }
  my $opt = {};
  foreach my $k (@{$self->{opt}})
    { 
    $opt->{$k} = 1;
    } 
  my $error = $self->_check_params ($request, $required, $opt);

  # if matched without error, but requested to throw error, do so
  $error = msg(450, $self->{throw} ) if !$error && $self->{throw};
    
  return ($self,$error);		# error (undef or error msg)
  }

sub _construct
  {
  my $self = shift;
 
  # default template is 'cmd_foo;type_bar' => bar.tpl 
  $self->{match} =~ /(^|;)type_(\w+)/;

  if ($self->{tpl} eq '')
    {
    $self->{tpl} = $2 || '';
    $self->{tpl} .= '.tpl' if $self->{tpl} ne '';
    }
  $self->{tpl} = 'unknown.txt' if $self->{tpl} eq '';

  # split match on ';' into "field_value" pairs
  my $fields = [ split /;/, $self->{match} ];
  $self->{matches} = [];
  foreach my $field (@$fields)
    {
    push @{$self->{matches}}, [ split /_/, $field ];
    }

  foreach my $k (qw/opt req nonempty carry/)
    {
    $self->{$k} = [ split /\s*,\s*/, $self->{$k} ];
    }

  $self;
  }

sub _check_params
  { 
  # check for empty params (params must be defined and not '', and not a
  # reference to an array), as well as optional params
  my ($self,$req,$required,$opt) = @_;
  
  # already had an error, so no more checks
  return if $self->{_error} ne '';

  # check for required and non-empty params beeing really non-empty
  foreach my $n (keys %$required)
    {
    if ((!exists $req->{$n}) || (!defined $req->{$n}) || ($req->{$n} eq ''))
      {
      return msg(459,$n,$req->{cmd} || 'unknown', $req->{type} || 'unknown');
      }
    }
  # check that we don't have anything except the required and optional params
  foreach my $k (keys %$req)
    {
    next if $k =~ /^(_|dirty$)/;		# skip internals
    if (! (exists $required->{$k} || exists $opt->{$k}))
      {
      return msg(460, $k, $req->{$k} || 'undef' );
      }
    }
  }

sub _replace_fields
  {
  my ($self,$request,$tpl) = @_;

  # if text contains something like: '##request-FIELD##', then
  # replace it by the field from $request->{FIELD}
  while ($tpl =~ /##request-(\w+)##/)
    {
    my $field = $1 || '';
    my $content = $request->{$field} || '';
    $tpl =~ s/##request-$field##/$content/g;
    }
  $tpl;
  }

sub template_name
  {
  my ($self,$request) = @_;

  $self->_replace_fields($request,$self->{tpl});
  }

sub output
  {
  my ($self,$request) = @_;
  
  $self->_replace_fields($request,$self->{output});
  }

sub title
  {
  my ($self,$request) = @_;
  
  $self->_replace_fields($request,$self->{title});
  }

sub type
  {
  my $self = shift;
  $self->{type};
  }

sub class
  {
  my $self = shift;

  return 'invalid' if $self->{_error};
  $self->{class};
  }

sub auth
  {
  my $self = shift;
  $self->{auth};
  }

sub sort_order
  {
  my $self = shift;

  ($self->{sort}, $self->{sort_by});
  }

sub carry
  {
  my $self = shift;

  @{$self->{carry}};
  }

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Request::Pattern -- an object containing one request pattern

=head1 SYNOPSIS

	use Dicop::Request::Pattern

	push @patterns, Dicop::Request::Pattern->new (
		match => 'cmd_status;type_main',
		req => 'id',
		opt => 'style',
		output => 'html',
		type => 'status',
		tpl => 'main.txt',
		auth => 0,
		class => 'admin',
		throw => 'error message',
	);

	# automatically checks the new Request against all the patterns
	# and selects the one fitting it (or generates an error in the
	# Request)
	$request = new Dicop::Request (
          id => 'req0001',
          data => 'req_0000=cmd_status;type_main',
	  patterns => \@patterns,
          );

	if ($request->error() ne '')
	  {
	  # error, no pattern matched
	  die ($request->error());
	  }

	  print "The request '", $request->as_request_string(), "' is valid.\n";
	  print "We should output ", $match->output($request), " with the title '",
		$match->title($request),"'\n";
	  print "We should read the template ", $match->template($request), "\n";
	  }

=head1 REQUIRES

perl5.8, Dicop::Base, Dicop::Item, Dicop::Event

=head1 EXPORTS

Exports nothing.

=head1 DESCRIPTION

Class to represent a pattern that represents a valid request. All requests can be
checked against this pattern to determine whether they are valid or not. In praxis a
list of all valid pattersn would be maintained and each request checked against each
pattern.

A I<request> in Dicop is simple a message passed between machines like the server,
clients or a proxy.

=head2 Storage

Pattern descriptions are stored in a flat file in text format and are read by
the code at startup.

=head2 Sample entry


	{
	match = "cmd_status;type_test"
	nonempty = "start end description jobtype charset"
	req = "id"
	opt = "style"
	output = "html"
	tpl = "test.txt"
	title = "Test Status Page"
	type = "status"
	class = "status"
	auth = 1
	}

=head2 Pattern properties

Below follows a detailed description on the possible pattern properties and their
meaning:

=head2 Sample entry

=over 2

=item match
	
	match = "cmd_status;type_test"

The patterns is valid for all requests that match this pattern. The order
is not important, so C<type_test;cmd_status> would work as well.
All params B<must> match exactly - otherwise the request pattern doesn't
match this request. It is possible to enter regular expressions for the
values, e.g.

	match = "cmd_status;type_/^(test|work)$"

Note the closing "/" is missing and the regexp must come last.

=item nonempty

	nonempty = "start end description jobtype charset"

These params must be non-empty (and also present). Default is "".

=item req

	req = "id"

These params must be present, but can be empty unless they are listed in
nonempty. Default is "". Any params in 'match' and "nonempty" are
automatically added to 'required' so you don't need to list them twice.

=item opt

	opt = "style"

These params are optional (and can be empty if they are not listed in
nonempty). Default is "style". If you don't want "style" to be optional,
set C<opt = "">.

=item output

	output = "html-table"

The type of output sent when this pattern matches. Valid are "html",
"html-table" or "text". Default is "html".

=item tpl

	tpl = "test.txt"

Name of the template file to reply if this pattern matches. Optional and
only neccessary if type = "html" or "html-table". If left empty, and type is
"html", the vaue will be "TYPE.tpl" where TYPE is the value of the type-param
of the request, e.g. for C<cmd_status;type_test> it would be "test".
This if course works only if "type" is an allowed, nonempty param.

=item title

	title = "Test Status Page"

The title string, only necc. if L<output> is "html" or "html-table".

=item type

	type = "status"

The type of the request. Types: "status", "info", "auth", "request",
"other". Default is "status". This is used to keep statistics about
request types.

=item class

	class = "status"

The class of the request. This is used to deny/allow requests based on
IPs and nets. Other then that, the class is not used. Possible are "admin",
"stats", "status" and "work". Default is "admin".

=item auth

	auth = 1

Set this to 1 to require user authentication (e.g. password and username)
for this request.
    
=item sort

	sort = "down"

The sort oder for output "html-table". Possible are "up", "upstr", "down"
and "downstr". The default is "up". The variants "upstr" and "downstr"
sort strings, while "up" and "down" are for numerical fields.

See also L<sort_by>.

=item sort_by

    	sort_by = "id"

Which field to sort the output by. Default is "id", and can be any field of
the objects to list. Only works for output of "html-table" or if the output
contains a list of objects. See also L<sort>.

=item carry

	carry = "job_id"

List of fields that need to be carried over for forms. These will be added
as hidden params to the form.
		
=item throw

	throw = "some error message"

If this request matched without an error, throw this error message and bail
out. Used to catch specific forbidden requests.

=back

=head1 METHODS

=head2 error

Get/set error message. Returns empty string in case of no error.

=head2 check

	($match, $error) = $pattern->check ( $request );

Check the given request of whether it matches this pattern (with or without
error) or not. Will return C<$match = undef> for no match, and
C<$match = $pattern> for a match. Upon C<$match> beeing equal to
C<$pattern>, C<$error> will indicate whether there was an error or not.

=head2 output

	$output_type = $pattern->output($request);

Returns the defined output for the request matching this pattern, or the empty
string for none.

=head2 template_name

	$tpl = $pattern->template_name();

Returns the defined name of the template for this pattern, or the empty string for
none. This will only be set if C<output_type()> equals 'html'.

=head2 type

	$type = $pattern->type($request);

Returns the type of the request matching this pattern.

=head2 title

	$title = $pattern->title($request);

Returns the title of the request matching this pattern.

=head2 sort_order

	($sort_order, $sort_by) = $pattern->sort_order();

Return the sort order ('up', or 'down') and the name of the field to
sort on. The default is C<('up', 'id')>.

=head2 auth

	$auth = $pattern->auth();

Returns a flag indicating whether we need user authentication (e.g. pwd and
username) for matching requests or not.

=head2 class

	$class = $pattern->class();

Returns the class of the request matching this pattern.

=head2 carry

        my $carry = $pattern->carry();

Return a list of fields that the form must include to carry over.

=head1 BUGS

None known yet.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

