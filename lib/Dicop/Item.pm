#############################################################################
# Dicop::Item - a base class representing data objects
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Item;
use vars qw($VERSION);
$VERSION = 1.05;	# Current version of this package
require  5.004;		# requires this Perl version or later

require Exporter;
@ISA = qw/Exporter/;
@EXPORT_OK	= qw( from_string );
use strict;

use Dicop::Event qw/crumble/;
use Dicop::Base qw/a2h h2a/;

{ # class data
  my $ids = {};

  sub new_id
    {
    my $class = ref(shift);

    $class =~ s/^(\w+)::(\w+)::(\w+)::.*/$1::$2::$3/;	# Data::Object::Foo and Data::Object::Foo::Bar share IDs
    $ids->{$class} = 0 unless defined $ids->{$class};
    my $i = shift;
    if (defined $i)
      {
      # use the supplied id, but keep record of highest
      $ids->{$class} = $i if $i ge $ids->{$class};
      return $i;
      }
    else
      {
      $ids->{$class}++; # just increment last used id
      return $ids->{$class};
      }
    }
  sub _highest_id
    {
    my $class = shift;
    $class =~ s/^(\w+)::(\w+)::(\w+)::.*/$1::$2::$3/;	# Data::Object::Foo and Data::Object::Foo::Bar share IDs
    $ids->{$class};
    }
  sub set_id
   {
    my $class = ref($_[0]) || $_[0];
    $class =~ s/^(\w+)::(\w+)::(\w+)::.*/$1::$2::$3/;	# Data::Object::Foo and Data::Object::Foo::Bar share IDs
    my $i = $_[1] || 0;

    $ids->{$class} ||= 0;
    $ids->{$class} = $i if $i > $ids->{$class};
    $ids->{$class};
    }

  my $templates = {};
  sub _get_template
    {
    my $class = ref($_[0]) || $_[0]; 
    return $templates->{$class} if exists $templates->{$class};
    undef;
    }

  sub _load_templates
    {
    # load templates for classes from file
    my $file = shift;

    require Dicop::Item::Template;

    my $class = 'Dicop::Item::Template';

    $templates = {};
    my $tpl = [ Dicop::Item::from_file ($file, $class) ];
    foreach my $p (@$tpl)
      {
      if (!ref($p) eq $class)
        {
        require Carp; Carp::croak ("$p is not a a reference to $class");
        }
      $p->_construct();
      # check for errors
      if ($p->error())
        {
        require Carp; Carp::croak ($p->error());
        }
      # index the templates under the class they describe
      # There should be only one, so check:
      my $class = $p->class();
      if (exists $templates->{$class})
	{
        require Carp; Carp::croak ("Template for class '$class' already defined.");
	}
      $templates->{$class} = $p;
      }
    $templates;
    }
# end of protected class vars
}

sub new
  {
  # create a new data thingy (with named parameters)
  my $class = shift;
  $class = ref($class) || $class;
  my $args;
  if (!defined $_[0])	# ()
    {
    $args = {};
    }
  else
    {
    $args = ref($_[0]) ? $_[0] : { @_ }; # ( reftohash ) or ( array )
    }
  my $self = {};
  bless $self, $class;
  $self->{dirty} = 0;
  $self->{_modified} = Dicop::Base::time();
  $self->_init($args);
  $self; 
  }

#############################################################################
# private, initialize self 

sub _init
  {
  my $self = shift;
  my $args = shift;
  my $check = shift || $self;
 
  $self->{_error} = '';
  $self->{id} = $self->new_id($args->{id});

  # init object with default fields based on template
  my $tpl = $self->_get_template();
   
  if ($tpl)
    {
    # found a template, so use it to init ourselves
    $tpl->init_object($self);
    }
  foreach my $k (keys %$args)
    {
    $self->{$k} = $check->_check_field($k,$args->{$k});
    }
  $self;
  }

sub _construct
  {
  # some things can not be done in _init, but must be done after the server
  # has replaced some numbers by references (f.i. to char sets)
  my ($self,$no_error) = @_;

  my $tpl = $self->_get_template();

  if ($tpl)
    {
    my @fields = $tpl->fields();
    foreach my $f (@fields)
      { 
      $tpl->construct_field($self,$f,$no_error);
      }
    }

  $self;
  }

sub _default
  {
  # provide default values
  my $self = shift;
  my $args = shift || {};
  my $check = shift || $self;

  foreach (keys %$args)
    {
    $self->{$_} = $check->_check_field($_,$args->{$_}) if !defined $self->{$_};
    }
  $self;
  }

#############################################################################

sub template
  {
  # return the template for this class or undef
  _get_template($_[0]);
  }

sub can_change
  {
  # return 1 if field cannot be changed, otherwise undef/0
  my ($self,$field) = @_;
 
  my $tpl = $self->_get_template();

  if ($tpl)
    {
    # found a template, so use it to check field
    return $tpl->can_change($field);
    }
  # else: we don't know, so let subclass provide a method to check this
  0;
  }

sub check
  {
  my $self = shift;
  
  $self->{_error} = '';
  $self->{_error} = "$self is no ref" unless ref $self;

  $self->{_error};
  }

sub error
  {
  my $self = shift;

  $self->{_error} = $_[0] if defined $_[0];
  $self->{_error};
  }

sub _check_field
  {
  my ($self,$field,$val) = @_;
  $field ||= "";

  # use template to check fields for max len, characters etc
  my $tpl = $self->_get_template();

  if ($tpl)
    {
    # found a template, so use it to init ourselves
    $val = $tpl->check_field($self,$field,$val);
    }
  $val;
  }

sub modified
  {
  # set yourself to the status of modifed (0 or 1) of argument, usually
  # called with 1 to flag modified, and reset to 0 after flush()
  my $self = shift;

  if (defined $_[0])
    { 
    my $m = shift;
    $self->{_modified} = $m; 
    $self->{_parent}->modified($m) if ref $self->{_parent};
    }
  $self->{_modified};
  }

sub parent
  {
  my $self = shift;

  $self->{_parent};
  }

sub dirty
  {
  # tag item as dirty, e.g. certain fields can no longer be edited
  # return dirty status
  my $self = shift;
  $self->{dirty} = shift if defined $_[0];
  $self->{dirty};
  }

sub _adjust_size
  {
  # used by chunk/job to calculate size from start/end
  # check whether start/end end in proper amount of fixed chars
  my $self = shift;

  if (defined $self->{_fixed} && ($self->{_fixed} > 0))
    {
    # get the internal Math::String::Charset obj
    my $set = $self->charset();
    my $c = $set->char(0);	# get the first char
    $c = $c x $self->{_fixed};
    die ("$self\::start must end in '$c$c$c' but is $self->{start}") 
     if $self->{start} !~ /$c$/;
    die ("$self\::end must end in '$c$c$c' but is $self->{end}") 
     if $self->{end} !~ /$c$/;
    }
  # from start & end calculate size, 'c'-'a' = 3, ('a','b','c')
  # we make as_number first, reason is that for simple|grouped:
  # 'c'-'a' = 3 ('a','b','c')
  # but for dictionary ones (assuming 'test', 'hello', 'world' in a chunk):
  # 'hello' - 'test' = 2 * scale + 1 ('test' not done, then 'world', 'hello')
  # if we would inc first, we would end up with (2+1) * scale vs. (2*scale)+1
  # $self->{_size} = $self->{end}->copy->bsub($self->{start})->as_number->binc; 
  $self->{_size} = $self->{end}->as_number->bsub($self->{start}->as_number())->binc; 

  $self;
  }

sub as_string
  {
  # convert yourself to a compact string form
  # example:
  # Dicop::Data::Item {
  #   blah => 9
  #   foo => 10
  #   name => "name"
  #   }

  # XXX TODO: that could use the hints from the Template to normalize output
  my $self = shift;
  my $txt;

  if (!defined $self->{_last_as_string} ||
      !defined $self->{_last_string} ||
      $self->{_modified} != 0)
    {
    $txt = ref $self; $txt .= " {\n"; my $v;
    foreach my $k (sort keys %$self)
      {
      next if $k =~ /^_/ || $k eq 'style'; 	# skip interals
      $v = $self->get($k);
      next if !defined $v;	# item is empty, skip writing it

      warn ("key $k in item ".ref($self). " (id $self->{id}) contains \\n or \\r") if $v =~ /(\n|\r)/;
      $v =~ s/\n/ /g;
      $v =~ s/\r//g;

      $v = 0 if !defined $v;			# NaN => undef => 0
      $v = '"'.$v.'"' if $v =~ /[^a-z0-9_\.,]/;
      next if $v eq '';
      $txt .= "  $k = $v\n"; 
      }
    $txt .= "  }\n";
    $self->{_last_string} = $txt;		# cache	
    $self->{_last_as_string} = Dicop::Base::time();
    }
  else
    {
    $txt = $self->{_last_string};		# return cached value
    }
  $txt;
  }

sub from_file
  {
  # reconstruct an object from the string form loaded from a file
  my ($file, $default_class) = @_;

  local $/ = undef;		# slurp mode
  open (FILE, $file) or return crumble("Cannot read $file: $!"); 
  my $data = <FILE>;
  close FILE;

  from_string($data,$default_class);
  }

sub from_string
  {
  # from a string (scalar or ref to scalar) re-create objects
  my ($text,$default_class) = @_;

  $text = $$text if ref $text; # make scalar if given reference

  die ("undefined text in from_string " . join(" ",caller()) . " ")
   if !defined $text;
  
  my @lines = split /\n/,$text;

  my (@list,$line,$self);
  while (@lines > 0)
    {
    $line = shift @lines;
    next if $line =~ /^\s*(#|$)/;	# skip comments
    if ($line =~ /^\s*([\w:]*)\s*\{/)
      {
      my $class = $1 || $default_class;
      $self->{_error} = "Undefined class", return if !defined $class; # ugh, error
      $self = $class->new();
      $line = shift @lines;
      while (defined $line && $line !~ /^\s*\}/)
        {
        $line = shift @lines and next if $line =~ /^\s*(#|$)/;	# skip comments
        if ($line =~ /^\s*([\w-]+)\s*=>?\s*\{/)
	  {
          # form of: " name => {\n some => 'foo',\n bar => 'baz',\n}"
	  my $name = $1; $line = shift @lines; my $val = '{ ';
	  # read in lines until we find \}\s*$/
	  while ($line !~ /^\s*\}\s*$/)
	    {
            $val .= $line unless $line =~ /^\s*#/;	# skip comments, too
	    $line = shift @lines;
	    }
          $val .= ' } ';
	  # untaint $val
          $val =~ /([-+\w\s\{}\()"'.,=><!\?@#:;üöäÜÖÄß%\n\/\\\[\]]+)/;
          $@ = undef;
          $self->put($name, eval($1));
	  if ($@)
	    {
	    require Carp; Carp::croak($@ . "\n tried eval($1)");
	    }
	  }
	else
	  {
	  $line =~ /^\s*([\w-]+)\s*=>?\s*\"?(.*?)\"?\s*$/;
          $self->put($1,$2);
	  }
        $line = shift @lines;
        }
      } 
    else
      {
      # ugh error
      $self->{_error} = "Illegal object format in string: '$line'";
      crumble ($self->{_error});
      } # end one object
    push @list,$self;
    }
  wantarray ? @list : $list[0];
  }

sub fields
  {
  # return a list of additional keys that must be included when generating
  # HTML representations/lists
  my $self = shift;

  my $tpl = $self->_get_template();
  return () unless $tpl;

  $tpl->fields();
  }

sub put
  {
  # convert data item from string back to internal representation
  my $self = shift;
  my ($var,$data) = @_;

  $self->{$var} = $self->_check_field($var,$data);

  }

sub get
  {
  # convert data item from internal representation to string (for saving)
  my ($self,$key) = @_;

  # XXX could also use Template to check for valid fields
  if (!exists $self->{$key} || !defined $self->{$key})
    {
    my $id = $self->{id} || 'unknown id';
    my $t = ref($self);
    return crumble "Error in $t $id: field '$key' does not exist!"
     if !exists $self->{$key};
    return crumble "Error in $t $id: field '$key' undefined!";
    }
  my $val = $self->{$key};
  my $ref = ref($val);

  if ($ref eq 'Math::String')
    {
    if ($self->{$key}->is_zero())
      {
      $val = '';
      }
    else
      {
      $val = a2h($self->{$key}) . ',' . $self->{$key}->as_number();
      }
    }
  elsif ($ref =~ /^Dicop::Data::/)
    {
    $val = $self->{$key}->{id};
    }
  elsif ($ref =~ /^Math::Big/)
    {
    $val = $val->bstr();
    }
  elsif ($ref eq 'ARRAY')
    {
    my $k = $self->{$key};
    return if @$k == 0;
    $val = '';
    foreach my $h (@$k)
      {
      if (ref($h) ne 'ARRAY')
        {
	$val .= $h . ',';
        }
      else
        {
        $val .= join ('_',@$h) . ',';
	}
      }
    $val =~ s/,$//;     # remove last ,
    }
  elsif ($ref eq 'HASH')
    {
    my $k = $self->{$key};
    return if scalar keys %$k == 0;
    $val = '';
    foreach my $h (sort keys %$k)
      {
      if (ref($k->{$h}) ne 'ARRAY')
        {
        $val .= $h . '_' . $k->{$h} . ",";
	#require Carp; Carp::croak ("$k->{$h} (key $key) is not an ARRAY ref");
        }
      else
        {
	$val .= $h . '_';
	my @togo = @{$k->{$h}}; shift @togo;
	foreach my $p (@togo)
          {
          my $pv = ref($p) ? $p->{id} : $p; $pv = '' unless defined $pv;
	  $val .= $pv . '_';
	  }
	$val =~ s/_$//;     # remove last _
	$val .= ',';
	}
      }
    $val =~ s/,$//;     # remove last ,
    }
  $val;
  }

sub get_as_hex
  {
  # convert data item from internal representation to hex string 
  # does nothing as default, override and add a2h() for the things you want to
  # convert as hex
  my ($self,$var) = @_;

  if (!exists $self->{$var})
    {
    require Carp;
    Carp::confess ("Illegal access to non-existing field '$var' of $self");
    return crumble ("Illegal access to non-existing field '$var' of $self");
    }
  $self->{$var};
  # return a2h("$self->{$var}");
  }

sub get_as_string
  {
  # convert data item from internal representation to string (for web display)
  my ($self,$var) = @_;

  if ($var =~ /^extra\d+/)		# extra0 etc are special
    {
    my $p = $self->{$var}; $p = '' unless defined $p;
    return $p;
    }

  if (!exists $self->{$var})
    {
    require Carp;
    Carp::confess ("Illegal access to non-existing field '$var' of $self");
    return crumble ("Illegal access to non-existing field '$var' of $self");
    }

  my $val = $self->{$var}; $val = '' unless defined $val;

  # type 'list' => return 'foo, bar'
  return join(", ", @$val) if ref($val) eq 'ARRAY';

  # if field is of type "foo_id", return id if possible
  $val = $val->{id} if ref($val) && exists $val->{id};

  my $tpl = $self->_get_template();
  return $val unless $tpl;

  # non-existant field?
  my $field = $tpl->field($var);
  return $val unless $field;

  my $type = $field->{type};

  # if template says field is of type "foo_id", return id if possible.
  # already handled with simpler test above
  #return $val->{id} if $type =~ /^.*_id$/;

  # if template says field is of type "time", return localtime()
  return scalar localtime($val) if $type eq 'time';
 
  # return a Yes/No for booleans 
  if ($type eq 'bool')
    {
    return $val ? "&sigmaf;" : 'No';
    }
  
  $val;
  }

sub flush
  {
  # flush any contained things to disk, not used here, override in sub class
  }

sub copy
  { 
  # copy an object including all sub objects
  my $self = shift;

  my $clone = {}; my $ref;
  foreach my $key (sort keys %$self)
    {
    $ref = ref($self->{$key});
    # make a shallow copy of references to other Dicop::Data structures
    if (!$ref || $key eq '_parent' || $ref =~ /Dicop::Data::/)
      {
      $clone->{$key} = $self->{$key};
      }
    elsif ($ref eq 'ARRAY')
      {
      $clone->{$key} = [ @{$self->{$key}} ];
      }
    elsif ($ref eq 'HASH')
      {
      Dicop::Item::copy($self->{$key});	# recursive
      }
    elsif ($ref =~ /^Math::String::Charset/)
      {
      $clone->{$key} = $self->{$key};	# no copy necc., share these
      }
    else
      {
      $clone->{$key} = $self->{$key}->copy();
      }
    }
  bless $clone, ref($self) if ref $self;	# check for recursion
  $clone;
  }

sub _from_string_form
  {
  # convert fields in @_ from string form ('303030', or '30,1') to Math::String
  my $self = shift;
  my $charset = shift;

  my $cs = $charset;
  $cs = $charset->charset() unless $cs->isa('Math::String::Charset');
  my $cs_id = $charset->{id} || 'unknown';

  foreach my $k (@_)
    {
    next if ref($self->{$k});			# if already object, skip

    # The field is one of the following forms:
    # "313233,1234",			(hex, number)
    # "303132"				(hex)
    # "len:1", "first:1", "last:1"

    if (h2a($self->{$k}) =~ /^(first|len|last):[0-9]+$/)
      {
      # length requested like len:3, but accidentily in hex, so convert back
      $self->{$k} = h2a($self->{$k});
      }
    if ($self->{$k} =~ /^(first|len|last):([0-9]+)$/)
      {
      my $method = $1; $method = 'first' if $method eq 'len';
      my $len = $2 || 0;
      # check for len:0 or first:0
      if ($len < 1)
        {
        $self->{_error} = "Length $len in $k='$self->{$k}' must be > 0";
        return;
        }
      my $rc = Math::String->new('',$cs)->$method($len);
      $self->{_error} =
       "$k ('$self->{$k}') is not a valid Math::String for set $cs_id"
        if $rc->is_nan();
      $self->{$k} = $rc;
      next;
      }

    my ($str,$num) = split /,/,$self->{$k}; $str = h2a($str);
    my $rc;
    if (defined $num)
      {
      $rc = Math::String->new( { str => $str, num => $num }, $cs );
      }
    else
      {
      $rc = Math::String->new ( $str, $cs );
      }
    $self->{_error} =
     "$k ('$self->{$k}') is not a valid Math::String for set $cs_id"
      if $rc->is_nan();
    $self->{$k} = $rc;
    }
  $self;
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Item - a base class representing data objects

=head1 SYNOPSIS

	use base Dicop::Item;

=head1 REQUIRES

perl5.004, Exporter, Dicop::Base, Dicop::Event

=head1 EXPORTS

Exports nothing.

=head1 DESCRIPTION

This module offers a C<new()> method which provides I<named parameters>, and
an C<_init()> method, which you can override to do any initialisation your
object needs.

=head1 FIELD

The following fields are present:

=over 2

=item _modified

=item dirty

=back

=head1 METHODS

=over 2

=item _default

Given a hash, initializes self with the values from the hash in case they are
not already defined:

	$self->SUPER::_default( { name => 'unknown', blah => 9 } );

=item dirty

Return the dirty flag. If given argument, sets the flag to that:

	print $item->dirty();		# 0 as default
	print $item->dirty(1);		# print 1

=item as_string

Return the object as compact string to be saved to file or printed etc. 

=item from_file

	$objects = [ Dicop::Item::from_file( $filename ) ];

Reconstruct objects from the string form loaded from a file, and return a list
of these objects.

=item from_string

	$objects = [ Dicop::Item::from_string( $string ) ];

From a string created with as_string, recreate the object(s). Returns a list
of objects or a single one, depending on context (scalar/list).

=item keys

	my @keys = $item->keys();

Returns a list of additional keys that must be included when generating
HTML representations/lists. The list of keys is defined by the template.

=item get_as_string

Convert data item from internal representation to a string suited for HTML
presentation.

=item get_as_hex

Just the same as get_as_string. You can override this method to convert certain
(or all) keys to hexify before returning them. Good for strings that could
contain unsafe or control characters.

=item get

Return the value of a specified field of the object:

        $object->get('foo');

=item put

Put the new value C<$value> into the field called C<$key>:

        $object->put($key,$value);

Note: For performance reasons, C<put()> does not call C<modified()>, so the object is not
flagged as modified afterwards. You need to call C<modified()> manually if you wish to
mak the object as modified.

=item change

Change a field's value after checking that the field can be changed (via
L<can_change>) and checking the new value. If the new value does not conform
to the expected format, it will be silently modifed (f.i. invalid characters
might be removed) and then the change will happen:

	$object->change('foo','bar');   # will change $object->{foo} to bar
					# if foo can be changed

=item can_change

Return true if the field's value can be changed.

	die ("Can not change field $field\n") if !$object->can_change($field);

=item flush

	$item->flush();

Override in a subclass to flush item to disk.

=item error

	$item->error();

Return a potential error status of the object, or the empty string if no error
occured.

=item copy

	$evil_twin = $item->copy();

Makes a deep copy of the object including copies of sub-objects.

=item parent

	my $parent = $self->parent();

Returns the parent object, e.g. the container we belong to.

=back

=head1 BUGS

None known yet.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut

