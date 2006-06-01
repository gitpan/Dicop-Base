#############################################################################
# Dicop::Request -- an object containing one message/request/answer
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Request;
use vars qw($VERSION $DEFAULT_PATTERNS $VALID);
$VERSION = 1.09;	# Current version of this package
require  5.008001;	# requires this Perl version or later

use Dicop::Item;
@ISA = qw/Dicop::Item/;
use strict;

use Dicop::Base qw/encode decode/;
use Dicop::Event qw/msg/;
use Dicop::Cache;

$DEFAULT_PATTERNS = undef;

BEGIN
  {
  $VALID = Dicop::Cache->new( timeout => 7200, limit => 2048 );
  }

#############################################################################
# private, initialize self 

sub _init
  {
  my $self = shift;
  my $args = shift;

  $self->{_error} = '';

  $self->{_id} = $args->{id} || '';
  $self->{_pattern} = undef;

  if ($self->{_id} eq '')
    {
    # Request needs valid id
    $self->error( msg(450, 'need non-empty ID') );
    return $self;
    }

  my $r = $args->{data} || '';

  if ($r eq '')
    {
    # Request needs valid data
    $self->error( msg(450, 'need non-empty data'), $r );
    return $self;
    }

  $self->error( msg(450, 'invalid ID') ) if $self->{_id} !~ /^req[0-9]{4}$/;

  $self->error( msg(450, 'need var name'), $r )
     if $r =~ /(^|;)_/; 			# 'val;_val' or '_val' are bad

  return $self if $self->{_error} ne '';	# on error, return

  # Check with our cache first. It caches valid request strings to shorten
  # the testing time. This assumes that the request-patterns don't change,
  # which is the case, since these are read only at startup. E.g. if a request
  # was valid, it will not be invalid now, and vice versa.
 
  my $is = $VALID->get($r);			# request is valid?
  $VALID->touch($r) if defined $is;		# if it was in cache, touch it
						# to make it newer

  if (defined $is && !ref $is && $is ne '')
    {
    $self->{_error} = $is;			# error
    return $self;				# was in cache as bad
    }
  
  # got a cached copy, so clone it into us, and return
  if (defined $is && ref($is))
    {
    # clone $is into $self
    foreach my $key (keys %$is)
      {
      next if $key eq '_id';			# skip this
      if (ref($is->{$key}) eq 'ARRAY')
        {
        $self->{$key} = [ @{$is->{$key}} ];
        }
      else
        {
        $self->{$key} = $is->{$key};
       }
      }
    return $self;
    }

  # not cached (uncertain), so check further

  my ($var,$p,@par);
  my @params = split /;+/,$r;		# ';+' => ignore multiple ';'
  foreach $p (@params)
    {
    if ($p !~ /_/)
      {
      # each part must be of the form 'var_val'
      $self->error( msg(450, 'invalid part'), $r );
      return $self;
      }
    ($var,@par) = split /_+/,$p;	# '_+' => ignore multiple '_'

    push @par, '' if @par == 0;		# var_; => (var => '')

    $var =~ tr/a-z0-9-//cd;
    # de-htmlize the parameters if the caller requested that
    if ($args->{encoded})
      {
      foreach my $k (@par)
	{
	$k = decode($k);		# $k is an alias to @par element
	}
      } 
    if ($var =~ /^[a-z-]+[0-9]*$/)
      {
      if (@par <= 1)
        {
        $self->{$var} = $par[0];
        }
      else
        {
        $self->{$var} = [ @par ];
        }
      }
    else 
      {
      # illegal var name
      $self->error( msg(450, "invalid var name '$var'"), $r );
      return $self;
      }
    } # end for each all params

  my $patterns = $args->{patterns} || $DEFAULT_PATTERNS;

  # no error so far, and not in cache, so do further detailed checks
  my ($match, $error);
  foreach my $pattern (@$patterns)
    {
    my ($cur_match, $cur_error) = $pattern->match($self);
  
    # if the pattern did not match, or it matched with an error, then
    # try further until we find a match without error
    if (defined $cur_match && (($cur_error || '') eq ''))
      {
      $match = $cur_match; $error = undef; last;
      }
    if (defined $cur_match && defined $cur_error)
      {
      # remember last case of match with error
      ($match, $error) = ($cur_match,$cur_error);
      }
    }

  if (defined $match && !defined $error)
    {
    $self->{_pattern} = $match;		# remember the pattern that defines us
    $VALID->put($r, $self);		# cache good results
    }
  else
    {
    #             error  or no  match at all,  put this error into the cache
    $self->error( $error  ||    msg(462)     , $r );
    }

  $self;
  }

sub error
  {
  my $self = shift;

  if (defined $_[0])
    {
    $self->{_error} = ($_[0] =~ /^req\d{4} / ? '' : "$self->{_id} ");
    $self->{_error} .= $_[0];
    $self->{_error} .= "\n" unless $self->{_error} =~ /\n\z/;
    $VALID->put($_[1], $self->{_error}) if defined $_[1];	# cache bad results
    }
  $self->{_error};
  }
 
sub as_request_string
  {
  # return yourself as a compact request string that can be sent to server
  my $self = shift;
  
  return undef if $self->{_error} ne '';
  my $s = "$self->{_id}=";
  foreach my $k (sort keys %$self)
    {
    next if $k =~ /^(_|dirty)/;	# skip internals
    if (ref ($self->{$k}) eq 'ARRAY')
      {
      if (@{$self->{$k}} > 0)
        {
        $s .= $k.'_';
        foreach my $v (@{$self->{$k}})
          {
	  $v = "$v";	# stringify objects		
	  $v = encode($v) if ($v !~ /^[a-zA-Z0-9]*\z/);
	  $s .= "$v,";
          } 
        chop $s;	# remove last ','
        $s .= ';';	# add ';' for next param	
        }
      }
    else
      {
      if (defined $self->{$k})
        {
	my $v = "$self->{$k}";
	$v = encode($v) if ($v !~ /^[a-zA-Z0-9]*\z/);
        $s .= $k.'_'."$v;";
        }
      }
    }
  chop $s;	# remove last ';'
  $s;
  }

sub copy
  {
  # create an exact copy of yourself
  my $self = shift;

  my $copy = {};
  bless $copy, ref($self);

  foreach my $key (keys %$self)
    {
    if (ref($self->{$key}) eq 'ARRAY')
      {
      $copy->{$key} = [ @{$self->{$key}} ];
      }
    else
      {
      $copy->{$key} = $self->{$key};
      }
    }
  $copy;
  }

sub fields
  { 
  my $self = shift;

  my @keys = ();
  foreach my $key (sort keys %$self)
    { 
    next if $key =~ /^(_|dirty$)/;
    push @keys, $key;
    }
  @keys;
  }

sub field
  { 
  # set a field of the object to another value
  my ($self,$field,$value) = @_;
  
  if (defined $value)
    {
    $self->{$field} = $value;
    $self->check();
    }
  $self->{$field}; 
  }

sub request_id
  {
  # change the request id, and return it
  my $self = shift;

  my $id = shift;
  if ((defined $id) && ($id =~ /^req[0-9]{4}$/))
    {
    $self->{_id} = $id;
    }
  $self->{_id};
  }

#############################################################################
# relay title, output, type etc from the matching request pattern

sub pattern
  {
  $_[0]->{_pattern};
  }

sub type
  {
  my $self = shift;

  return undef if !defined $self->{_pattern};
  $self->{_pattern}->type();
  }

sub class
  {
  my $self = shift;

  return 'invalid' if !defined $self->{_pattern} || $self->{_error};
  $self->{_pattern}->class();
  }

sub output
  {
  my $self = shift;

  return undef if !defined $self->{_pattern};
  $self->{_pattern}->output($self);
  }

sub title
  {
  my $self = shift;

  if ((!defined $self->{_pattern}) || $self->{_error})
    {
    warn ("Access to title for illegal request: " . $self->{_error});
    return undef;
    }
  $self->{_pattern}->title($self);
  }

sub template_name
  {
  my $self = shift;

  return undef if !defined $self->{_pattern};
  $self->{_pattern}->template_name($self);
  }

sub auth
  {
  my $self = shift;

  return 1 if !defined $self->{_pattern} || $self->{_error};
  $self->{_pattern}->auth();
  }

sub sort_order
  {
  my $self = shift;
  
  my @s = ('up','id');

  # pattern defines the default
  if ($self->{_pattern})
    {
    @s = $self->{_pattern}->sort_order();
    }
     
  # if sort and sortby are defined in the request, they have priority
  $s[0] = $self->{sort} if exists $self->{sort} && $self->{sort} =~ /^(up|down|upstr|downstr)\z/;
  $s[1] = $self->{sortby} if exists $self->{sortby} && $self->{sortby} =~ /^[a-z]+\z/;

  # return sort (direction) and sortby (field to sort on)
  @s;
  }

sub carry
  {
  my $self = shift;

  return $self->{_pattern}->carry() if $self->{_pattern};
  ();
  }

#############################################################################

sub is_auth
  {
  my $self = shift;

  (($self->{_error} eq '') && $self->{_pattern}->{type} eq 'auth') <=> 0;
  }

sub is_info
  {
  my $self = shift;

  (($self->{_error} eq '') && $self->{_pattern}->{type} eq 'info') <=> 0;
  }

sub is_request
  {
  my $self = shift;

  (($self->{_error} eq '') && $self->{_pattern}->{type} eq 'request') <=> 0;
  }

sub is_form
  {
  my $self = shift;

  (($self->{_error} eq '') && $self->{_pattern}->{type} eq 'status') <=> 0;
  }

1;
__END__

#############################################################################

=pod

=head1 NAME

Dicop::Request -- an object containing one message/request/answer

=head1 SYNOPSIS

	use Dicop::Request;
	use Dicop::Request::Pattern;

	my $pattern1 = Dicop::Request::Pattern->new( ... );
	my $pattern2 = Dicop::Request::Pattern->new( ... );

	$request = new Dicop::Request (
          id => 'req0001',
          data => 'req_0000=cmd_status;client_5',
	  patterns => [ $pattern1, $pattern2, ... ],
          );

	print $request->error();	# request was ok?

=head1 REQUIRES

perl5.8.3, Dicop::Base, Dicop::Item, Dicop::Event

=head1 EXPORTS

Exports nothing.

=head1 DESCRIPTION

Class to represent a request. A request is both something the client sends
to the server as well as the return answer from the server. A more better
appropriate name would be "message".

=head1 METHODS

=head2 error

Get/set error message. Returns empty string in case of no error.

=head2 copy

Create an exact copy of yourself.

=head2 check

	$request->check ( $data, $validator);

Applies self-check and set error string on error.

=head2 request_id

Get/set the request's id:

	$request->request_id('req0003');	# set
	print $request->request_id();		# get and print

=head2 as_request_string

Returns the request as a compact request string that can be sent as an URL
parameter to the server:

	$request->as_request_string();		

This will give something like:

	req0002=cmd_status;type_main

=head2 pattern

	$request->pattern();

Return the request pattern that this request matched, or undef for none (in
case of errors). See L<Dicop::Request::Pattern>.

=head2 class

	$request->class();

Return the class of the request. The type stems from the pattern this request
matches and is defined in an external textfile together with the pattern.
See L<Dicop::Request::Pattern>.

=head2 type

	$request->type();

Return the type of the request. The type stems from the pattern this request
matches and is defined in an external textfile together with the pattern.
See L<Dicop::Request::Pattern>.

=head2 output

	$request->output();

Return the output type of the request. The type stems from the pattern this
request matches and is defined in an external textfile together with the
pattern.
See L<Dicop::Request::Pattern>.

=head2 title

	$request->title();

Return the output title for requests of C<output() eq 'html'>. The type stems
from the pattern this request matches and is defined in an external textfile
together with the pattern.
See L<Dicop::Request::Pattern>.

=head2 template_name

	$request->template_name();

Return the template file that should be used for this request. The template
file name stems from the pattern this request matches and is defined in an
external textfile together with the pattern.
See L<Dicop::Request::Pattern>.

=head2 auth

	$request->auth();

Return a flag on whether this request needs a password or not.
The flag stems from the pattern this request matches and is defined in an
external textfile together with the pattern.
See L<Dicop::Request::Pattern>.

=head2 field

Set a field of the request object to another value:

	$equest->field('foo';'bar');	# set $request->{foo} to 'bar'

=head2 get_as_string

Return a field of the object as an ASCII string suitable for HTML output:

	$result->get_as_string('foo');

=head2 get_as_hex

Return a field of the object as an hexified string, or as a fallback, as normal
string via get_as_string. The hexify happens only for certain special fields,
all other are returned as simple strings:

	$result->get_as_hex('foo');

=head2 change

Change a field's value after checking that the field can be changed (via
L<can_change>) and checking the new value. If the new value does not conform
to the expected format, it will be silently modifed (f.i. invalid characters
might be removed) and then the change will happen:

	$object->change('foo','bar');   # will change $object->{foo} to bar
					# if foo can be changed

=head2 carry

	my $carry = $request->carry();

Return a list of fields that the form must include to carry over.

=head2 can_change

Return true if the field's value can be changed.

	die ("Can not change field $field\n") if !$object->can_change($field);

=head2 is_form(), is_auth(), is_info(), is_request()

	if ($request->is_form())
	  {
	  ...
	  }

Returns true if the request is of the tested type (form, auth, info or request).
Returns false if the request is invalid (e.g. an error occured).

=head2 sort_order()

	my ($sort_dir, $sort_by) = $request->sort_order();

Return sort direction and the field to sort on, for example
C<< 'up','id') >>.

=head1 BUGS

None known yet.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

