
# three empty subclasses based on Dicop::Item
package Dicop::Data::Subclass;

use base qw/Dicop::Item/;

package Dicop::Data::Subclass::Sub;

use base qw/Dicop::Item/;

package Dicop::Data::SomeSubclass;

use base qw/Dicop::Item/;

package Dicop::Item::SubSubclass;

use base qw/Dicop::Item/;

sub parent
  {
  Dicop::Handler::Foo->new();
  }

package Dicop::Handler::Foo;

use base qw/Dicop::Item/;

sub get_object
  {
  my ($self, $req) = @_;

  # for double _construct test
  die ("expected ID, got " . $req->{id}) if ref($req->{id});

  Dicop::Data::SomeSubclass->new();
  }

package main;

1;
