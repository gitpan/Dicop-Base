#############################################################################
# Dicop::Item::Template - an object defining Dicop::Item subclasses
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Item::Template;
use vars qw($VERSION);
$VERSION = 0.02;	# Current version of this package
require  5.008;		# requires this Perl version or later

use Dicop::Item;
@ISA = qw/Dicop::Item/;
use strict;
use vars qw($VALID);

use Dicop::Base qw/encode decode/;
use Dicop::Event qw/msg/;
use Dicop::Security qw/valid_ip/;

#############################################################################
# private, initialize self 

sub _init
  {
  my ($self,$args) = @_;

  $self->SUPER::_init($args,$self);
  $self->SUPER::_default( {
    class => 'Dicop::Item',
    }, $self );

  $self;
  }

sub _construct
  {
  # turn 'field = " some => { test => foo }"' into { some => { test => foo, }, }
  my $self = shift;

  my $f = $self->{fields} || '';
  $self->{fields} = eval " { $f }"
    unless ref ($self->{fields}) eq 'HASH';
  if ($@ || ref($self->{fields}) ne 'HASH')
    {
    die ("Error in eval for template of $self->{class}: ");
    } 

  $self->{fake_keys} ||= '';
  
  $self->{fake_keys} = [ sort( split /\s*,\s*/, $self->{fake_keys}) ]
    unless ref ($self->{fake_keys}) eq 'ARRAY';

  # create only unique names (avoid doubles doubles)
  my %known = map { $_ => 1 } ( 
    keys %{$self->{fields}}, 		# known fields
    @{$self->{fake_keys}},		# plus fake ones
    'id'				# plus 'id' (always present)
    );

  $self->{_known_fields} = [];
  # warn, if one key contains something else than \w
  $f = $self->{fields};
  my @keys = sort keys %known;
  foreach my $key ( @keys )
    {
    next if exists $f->{$key} && exists $f->{$key}->{virtual};

    if ($key =~ /[^\w+-]/i)
      {
      require Carp;
      Carp::confess ("Keyname '$key' contains illegal characters");
      }
    push @{$self->{_known_fields}}, $key;
    }

  # changeable fields are automatically noadd => 1
  foreach my $key (keys %{$self->{fields}})
    {
    my $field = $self->{fields}->{$key};
    $field->{noadd} = 1 if !defined $field->{noadd} && $field->{changeable};
    }
  
  foreach my $key (qw/include description help/)
    {
    $self->{$key} ||= '';
    $self->{$key} =~ s/\\n/\n/g;	# turn '\n' into "\n"
    }

  # check that only the relevant fields are present
  $self->check();
  }

sub check
  {
  my $self = shift;

  foreach my $key (keys %$self)
    { 
    next if $key =~ /^_/;		# ignore internals

    return $self->error("Key '$key' not allowed in template for class $self->{class}")
      if $key !~ 
       /^(class|dirty|description|fake_keys|fields|help|id|include)\z/;
    }
  # 
  foreach my $key (keys %{$self->{fields}})
    {
    foreach my $k (keys %{$self->{fields}->{$key}})
      {
      return $self->error("Key '$k' for field '$key' not allowed in template for class $self->{class}")
        if $k !~ 
         /^(addrank|addindend|addoption|changeable|def|description|editable|editindend|editoption|editrank|editlen|filter|help|min|max|maxlen|name|noadd|refresh|selector|sort|type|valid|virtual)\z/;
      }
    }
  }

#############################################################################

sub class
  {
  my $self = shift;

  return undef if $self->{_error};
  $self->{class};
  }

sub include
  {
  my $self = shift;

  return undef if $self->{_error};
  $self->{include} || '';
  }

sub description
  {
  my $self = shift;

  return undef if $self->{_error};
  $self->{description} || '';
  }

sub help
  {
  my $self = shift;

  return undef if $self->{_error};
  $self->{help} || 'No further help available.';
  }

#############################################################################
# routines to init an object based on that template

sub init_object
  {
  # init fields in that object with default values
  my ($self,$obj) = @_;

  my $f = $self->{fields};
  foreach my $field (keys %$f)
    {
    my $def = $f->{$field}->{def}; $def = '' unless defined $def;
    $obj->{$field} = $def if !defined $obj->{$field};
    }

  }

sub check_field
  {
  # check the new value for a field in object to still conform to rules
  my ($self,$obj,$field,$val) = @_;

  if (!exists $self->{fields}->{$field})
    {
    # if we don't know about the field, don't do checks
    # XXX TODO: warn?  
    return $val;
    }
  # fetch type of the field
  my $f = $self->{fields}->{$field};
  my $type = $f->{type} || '';

  # checks depending on type
  $val =~ s/[\"\'\`\=\n\t\r\b]//g 	if $type =~ /^(string|file)\z/;
  $val = ($val || 0)+0.0 		if $type eq 'float';
  $val = int($val||0) 			if $type eq 'int';
  $val = ($val ? 'on' : '')		if $type eq 'bool';

  # matches some class::name, so turn into object if not already
  # not yet for Math::String, because these need an additional charset
  if ($type =~ /::/ && $type !~ /Math::String/)
    {
    $val = $type->new( $val ) unless ref($val);
    # construct min/max also as objects, to preserve the class upon checks
    $f->{min} = $type->new( $f->{min} ) if defined $f->{min} && !ref($f->{min});
    $f->{max} = $type->new( $f->{max} ) if defined $f->{max} && !ref($f->{max});
    }

  # for numeric types, check min/max 
  $val = $f->{min} if defined $f->{min} && $val < $f->{min};
  $val = $f->{max} if defined $f->{max} && $val > $f->{max};
  
  # XXX TODO: ip4 only
  if ($type =~ /^(mask|ip)\z/)
    {
    $val =~ s/[^0-9\.]//g;			# remove spaces etc
    $obj->error("'$val' is not a valid IP or netmask.") 
      unless valid_ip($val); 			# stricter check
    }
  
  # XXX TODO: other checks depending on type go here

  # check maxlen if specified and cut string to lenght
  my $maxlen = $self->{fields}->{$field}->{maxlen} || 0;
  $val = substr($val,0,$maxlen) if $maxlen > 0 && length($val) > $maxlen;
 
  # modified value is returned
  $val;
  }

sub construct_field
  {
  # turn fields from text strings into references to objects
  my ($self,$obj,$field,$no_error) = @_;

  if (!exists $self->{fields}->{$field})
    {
    # if we don't know about the field, don't do anything
    # XXX TODO: warn?   
    return;
    }
  # fetch type of the field
  my $f = $self->{fields}->{$field};
  my $type = $f->{type} || '';

  # matches FOO_id, so turn into object if not already
  if ($type =~ /^([a-z]+)_id\z/i)
    {
    if (!ref($obj->{$field}) && ($obj->{$field}||'0') ne '0')
      {
      $obj->{$field} = $obj->parent()->get_object( { type => $1, id => $obj->{$field} }, $no_error );
      }
    }

  if ($type eq 'list')
    {
    # turn 'foo, bar' into [ 'foo', 'bar' ]
    if (!ref($obj->{$field}))
      {
      $obj->{$field} = [ split /\s*,\s*/, $obj->{$field} ];
      }
    }

  # matches some class::name, so turn into object if not already
  # not yet for Math::String, because these need an additional charset
  if ($type =~ /::/ && $type !~ /Math::String/)
    {
    $obj->{$field} = $type->new( $obj->{$field} )
      unless ref($obj->{$field});
    # construct min/max also as objects, to preserve the class upon checks
    $f->{min} = $type->new( $f->{min} ) if defined $f->{min} && !ref($f->{min});
    $f->{max} = $type->new( $f->{max} ) if defined $f->{max} && !ref($f->{max});
    }
  }

sub can_change
  {
  # return whether a field is editable/changeable
  my ($self,$field) = @_;
  
  my $f = $self->{fields}->{$field};

  # XXX TODO: allow object to override this depending on its own state
  $f->{editable} || $f->{changeable} || 0;
  }

sub editable_fields
  {
  # return a list of all fields that are editable (e.g. need to appear on the
  # edit form)
  my ($self) = @_;

  my @list = ();
  foreach my $field (sort keys %{$self->{fields}})
    {
    push @list, $field if $self->{fields}->{$field}->{editable};
    }
  @list;
  }

sub changeable_fields
  {
  # return a list of all fields that are changeable
  my ($self) = @_;

  my @list = ();
  foreach my $field (sort keys %{$self->{fields}})
    {
    push @list, $field if $self->{fields}->{$field}->{changeable};
    }
  @list;
  }

sub addable_fields
  {
  # return a list of all fields that are settable when adding an object
  my ($self) = @_;

  my @list = ();
  foreach my $field (sort keys %{$self->{fields}})
    {
    push @list, $field unless $self->{fields}->{$field}->{noadd};
    }
  @list;
  }

sub fields
  {
  # return a list of existing fields, in sorted order
  my $self = shift;

  @{$self->{_known_fields}};
  }

sub field
  {
  # return a field as a hash containing things like
  # { type => 'string', minlen => 1, }
  my ($self,$field) = @_;

  return $self->{fields}->{$field} if exists $self->{fields}->{$field};
  undef;		# error, non existing field
  }

sub fields_of_type
  {
  # return a list of existing fields, in sorted order
  my ($self,$type) = @_;

  my @fields;
  my $f = $self->{fields};
  foreach my $field (keys %$f)
    {
    push @fields, $field if exists $f->{$field}->{type} && $f->{$field}->{type} eq $type;
    }
  @fields;
  }

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Item::Template - an object defining Dicop::Item subclasses

=head1 SYNOPSIS

	use Dicop::Request::Template

	push @templates, Dicop::Item::Template->new (
		class => 'Dicop::Item::Subclass',
		fields => "name => { maxlen => 128, def => 'some name' }",
	);

=head1 REQUIRES

perl5.8.3, Dicop::Base, Dicop::Item, Dicop::Event

=head1 EXPORTS

Exports nothing.

=head1 DESCRIPTION

Templates are stored as text in a file, and are read upon startup to provide
descriptions and rules for objects. They are used to check objects for being
valid, as well as to restrict user input, construct automatically forms
for objects to be added or edited.

Each template carries a list of valid fields for items of the class
that the template is valid for, stored under C<fields>.

Each of these fields can have some properties that describe that
field, for instance the default value, the maximum length etc.

In addition, the template knows the class of objects it belongs to, some
help and descriptions etc.

=head2 Example

	{
	  class = Dicop::Item::SubSubSubclass
	  help = "Some help text"
	  description = "Some description text"
	  fields => {
	    name => { def => 'name', maxlen => 128, editable => 1, help => 'The name of the object', type => 'string' },
	    description => { maxlen => 256, editable => 1, help => 'A short description of the object/item', type => 'string', },
	    my_type => {
 	      selector => 'radiobutton',
	      editable => 1,
	      help => 'Select the type',
	      type => 'int',
	      addrank => 1,
	      addindend => 1,
	      editrank => 2,
	      editindend => 0,
	      valid => { 2 => 'Foo bar type', 5 => 'frobnozle', },
	      sort => 'name', 
	    },
	    my_int => { min => 1, max => 3, def => 2, help => 'a number between 1 and 3', },
	    my_virtual => { min => 1, max => 3, def => 2, editlen => 3, virtual => 2, },
	    include = "##include_someform.inc##"
	  }
	  fake_keys = "foobar"
	}

=head2 Valid keys for a template

Here is the list of known keys for each template:

=over 2

=item class

The class this template applies to. Example: 'Dicop::Item::Subclass'

=item description

A short description of this class.

=item help

A short help text that will appear when editing/adding objects of this
class.

=item fake_keys

A commata seperated list of fake key names. See L<fields> below.

=item fields

A hash containing all the valid fields. See below for a list of
L<valid properties for each field>.

=item include

Special code that should be inserted last on an add form.

=back

=head2 Valid properties for each field

Each field (see L<fields> above) has a list of properties. Here follows
an overview of all valid properties and a short description
of their meaning:

=over 2

=item addrank

The rank of this field on the add form. Fields with a low rank will
be shown first, higher ranks later. Fields with no rank count will
be shown last, in the order as determined by sorting their name.

=item addindend

The indend level of this field on the add form. Default is either the
L<editindend> or 0. Values of 0..3 work best.

=item addoption

A hash with additional options that should be selctable by the user
on an I<add> form.

	addoption => { 0 => 'Add a new case', }

This would add a new selectable option named "Add a new case" with the
value "0" to the list of allowed values when adding something.

=item changeable

The field can be changed, but is not automatically put on the
edit form. This is for the support for extra fields, e.g. that
sometimes are on the form, and sometimes not. 

=item def

The default value for this field.

=item description

A short description of the field. When not defined, L<help> is
used instead. Since C<help> is presented on the forms, 
C<description> can be used to overwrite the description for the
auto-doc feature.

=item editable

If true, this field is editable and will appear on edit forms for
this object type.

=item editindend

The indend level of this field on the edit form. Default is 0.
Values of 0..3 work best.

=item editoption

A hash with additional options that should be selctable by the user
on an I<edit> form.

	editoption => { 0 => 'Discard', }

This would add a new selectable option named "Discard" with the
value "0" to the list of allowed values when editing something.

=item editrank

The rank of this field when creating an edit form. Lowest ranks come
first, and all fields without any rank are added last, sorted by their
name.

=item editlen

The rank of this field on the change/edit form. Fields with a low rank will
be shown first, higher ranks later. Fields with no rank count will
be shown last, in the order as determined by sorting their name.

=item filter

	filter => 'type_simple',

Defines a filter field name and a filter string, seperated by C<_>. The
field name of the item must match the filter string, or otherwise the
item is not included in option lists on forms. The sample filter above
would, for instance, only allow objects when
C<< $item->{type} eq 'simple' >>.

=item help

A short help text that describes the field.

=item min

	min => 1,

The minimum value of the field. If set, it will be made sure that the value
is at least C<min>. Set C<min> only for integer types!

=item max

	max => 10,

The maximum value of the field. If set, it will be made sure that the value
is not bigger than C<max>. Set C<max> only for integer types!

=item maxlen

The maximum length in bytes of the contents of this field.

=item name

The name that will appear of forms without the trailing ':', e.g.:

	name => 'Passwort'

=item noadd

If true, the field will not appear on add forms.

=item refresh

If true, the a little 'refresh' (refresh this form) button will appear
next to this input field.

This will add '_refresh' to the C<selector> name (see below).

=item selector

	selector => 'radio',

The selector to use to build the entry form for the user. Usually this is autodetermined
depending on C<type> (see below), but can be overridden here. Valid selectors depend
on the templates that are available (C<editfield_radio.inc> must be available
if C<selector => 'radio'>), but some examples are below:

	radio		only one button active at a time
	select		a dropdown box of selections, only one at a time
	check		checkbox(es) that allow multiple selections

=item sort

If set, the given a list of items (either via valid or like case_id) will be sorted
on their strings (e.g. the things the user can select via the dropdown box).

=item type

The type. Here is a list of currently valid types:

	string		for general strings, numbers etc
	int		for integers
	float		for floats
	file		a file (or an string)
			Fields of this type will carry a 'Browse'
			button on add/edit forms
	dir		like file, but the user can select a directory
	time		time in seconds since 1970
	foo_id		ID of an object of type 'foo'
	Class::Name	an object of the class 'Class::Name' (this type
			is determined by the '::'!)

If unsure, use type 'string'.
	
=item valid

Specifiy a list of valid values for that field. There are three ways to
accomplish that:

A scalar:

	valid => 'some_method_that_returns_an_array_ref',

The method named must return either an array ref or a hash ref.
These arrays or hashes are build like the two other examples below.

The second way is a hash with a list of keys that map valid values for
this field to their descriptions for a form:

	valid => { 3 => 'Running', 4 => 'Solved', 6 => 'Suspended' }

This would allow the user to select between the three settings 'Running',
'Solved' and 'Suspended' and nothing else. The selection will be in
a list box and only one of the options can be selected at any time.

The third way is an array ref like this:
	
	valid => [
	  0, bit0 => 'Sunshine',
	  1, bit1 => 'Rain',
	  2, bit2 => 'Clouds',
	],

With this, multiple checkboxes will be used to let the user select each option on
its own. The first column is the bit number, the second the name of the
checkbox that will appear on the edit form, and the last is the text the user
will actually see beside each checkbox.

In short:

A hash will let the user select only one item at a time. By default this is a
dropdown list, but this can be overriden with C<selector> (see above).

An array will let the user select multiple items together. Per default this will
be a list of checkboxes.

=item virtual

If true, makes the field virtual, e.g. it is not present in the object. This is
usefull for fields that only appear on the add form. Without 'virtual', the
field would be included in L<fields()> and thus the code replacing it
in templates would try to access a no-longer existing field.

=back

=head1 METHODS

=over 2

=item error

Get/set error message. Returns empty string in case of no error.

=item class

	my $class = $template->class();

Return the class of objects this template belongs to.

=item include

	my $include_text = $template->include();

Return text to be included into form.

=item description

	my $description = $template->description();

Return a short description for all objects that are defined by this template.

=item help

	my $help_text = $template->help();

Return a short help text that helps the user when adding this object.

=item init_object

	$template->init_object ($object);
  
Init fields in that object with default values.

=item check_field

	$template->check_field ($object, $fieldname);

Check field in an object after a change to still conform to rules,
modifying it if neccessary.

=item construct_field

	$template->construct_field ($object, $fieldname);

Turn field from text string into references to object.

=item changeable_fields

	my @changeable_fields = $template->editable_fields();

Returns a list of all fields that are changeable, but should not appear
automatically on the edit form.

=item editable_fields

	my @edit_form_fields = $template->editable_fields();
  
Returns a list of all fields that are editable and must appear on the
edit form.

=item addable_fields

	my @add_fields = $template->addable_fields();
  
Returns a list of all fields that the user must fill in to add an object
defined by this template.

=item fields

	my @fields = $template->fields();
  
Returns a list of all fields that the template has.

=item fields_of_type

	my @fields = $template->fields_of_type('bool');
  
Returns a list of all fields that match the given type.

=item field

	$field = $template->field('somefieldname');
  
Teturn a field as a hash containing things like
C<< { type => 'string', minlen => 1, } >>.

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

