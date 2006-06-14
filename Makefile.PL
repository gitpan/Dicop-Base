use ExtUtils::MakeMaker;
require v5.8.1;
use strict;
use lib 'lib';		# if we bundled some modules with the
			# distribution, try to find these first
			# (otherwise old core modules would crop up)

sub MY::metafile {
  package MY;
  my $self = shift;
  if (!eval { require YAML; 1 })
  {
    warn ("YAML not installed, will not override META.yml");
    return $self->SUPER::metafile_target(@_);
  };

  require YAML::Node;
  my $node = YAML::Node->new({});

  for my $k (qw/
     AUTHOR ABSTRACT VERSION/)
    { 
    $node->{ lc($k) } = $self->{$k};
    }
  $node->{name}			= $self->{DISTNAME};
  $node->{license}		= 'gpl';
  $node->{distribution_type}	= 'module';
  $node->{generated_by}		= "$self->{DISTNAME} version $self->{VERSION}";
  $node->{installdirs}		= 'site';
  $node->{requires}		= $self->{PREREQ_PM};

  my $dump = YAML::Dump( $node );

  $dump =~ s/^(.*)$/\t\$(NOECHO) \$(ECHO) "$1" >>META.yml/gm;
  $dump =~ s/>>META\.yml/>META.yml/;

  "metafile:\n$dump";
}

use Dicop::Base;	# for VERSION and BUILD
my $version = $Dicop::Base::VERSION;
# for releases, omit the BETA VERSION
$version .= "_$Dicop::Base::BUILD" if $Dicop::Base::BUILD > 0;

# Dicop/Data/Client/LWP.pm needs HTTP::Request, which means we need libwww and
# thus also HTML::Parser, which in turn needs HTML::Tagset

WriteMakefile(
    'NAME'		=> 'Dicop::Base',
    'VERSION'		=> $version,
    'ABSTRACT'		=> 'basics for a Dicop HTTP server/client',
    'AUTHOR'		=> 'BSI',
    'PREREQ_PM'		=> { 
		'Digest::MD5' => 2.09,
		'Mail::Sendmail' => 0.77,
		'HTML::Tagset' => 3.03,
		'HTTP::Request' => 1.24,
		'Math::BigInt' => 1.77,
		'Math::String' => 1.27,
		'Time::HiRes' => 1.2,
		'File::Spec' => 0.82,
		'Test::More' => 0.47,
		'Net::Server' => 0.86,
    },
    'PREREQ_FATAL' => 1,
);
