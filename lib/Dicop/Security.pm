#############################################################################
# Dicop::Security - routines for authentication, checks, security
#
# (c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006
#
# DiCoP is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# See the file LICENSE or L<http://www.bsi.de/> for more information.
#############################################################################

package Dicop::Security;
$VERSION = '2.02';	# Current version of this package
require  5.004;		# requires this Perl version or later

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK	= qw(
		valid_ip valid_net 
                ip_is_in_net
		ip_is_in_net_list
		ip_matches
                hash_pwd valid_user
                );
use strict;
use Digest::MD5;
use Math::BigInt;

sub valid_ip
  {
  # take one ip definition and return true if it is valid
  my ($ip) = shift;

  return 0 if !defined $ip;
  return 0 if $ip !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  my @parts = split /\./, $ip;
  foreach my $part (@parts)
    {
    return 0 if $part < 0 || $part > 255;	# 280.1.1.2 is not valid
    }
  1;						# is valid
  }

sub valid_net
  {
  # take one net definition and return true if it is valid
  my ($input) = shift;

  return 1 if $input =~ /^(any|none)$/;

  my ($ip,$net) = split /\//, $input;
  return 0 unless valid_ip($ip);
  $net = '32' if !defined $net;
  return 0 if $net eq '' || $net !~ /^(32|24|16|8|0)$/;
  return 0 if $net eq '0' && $ip ne '0.0.0.0';
  my @parts = split /\./, $ip;
  if ($net eq '24')
    {
    return 0  if $parts[3] != 0;
    }
  if ($net eq '16')
    {
    return 0  if $parts[3] != 0 || $parts[2] != 0;
    }
  if ($net eq '8')
    {
    return 0  if $parts[3] != 0 || $parts[2] != 0 || $parts[3] != 0;
    }
  1;						# is valid
  }

sub ip_is_in_net
  {
  # take one (source) ip, and one check ip/net and then check whether source
  # is inside the net (or matches the check ip).
  # so 127.0.0.1 matches 127.0.0.1/32 and 127.0.0.0/24
  # return 0 for match, 1 for no match and <0 for error
  my ($ip,$net) = @_;

  return -1 unless valid_ip($ip);
  return -2 unless valid_net($net);

  return 0 if $net eq 'none';				# never okay
  return 1 if $net eq 'any';				# always okay

  my ($ip_match,$net_match) = split /\//, $net;
  $net_match = 32 if !defined $net_match;

  my @parts = split /\./, $ip;
  my @parts_match = split /\./, $ip_match;
  my $count = $net_match >> 3;				# /32 => 4, /0 => 0
  my $i = 0;
  while ($count-- > 0)
    {
    return 0 if $parts[$i] != $parts_match[$i];  	# not matched
    $i++;
    }
  1;							# is okay
  }

sub ip_is_in_net_list
  {
  # take one IP and a list of networks, and check whether the IP is in any
  # of the networks
  my ($ip,$nets) = @_;

  foreach my $net (@$nets)
    {
    my $r = ip_is_in_net($ip,$net);
    return $r if $r != 0;			# error (<0) or match (1)
    }
  0;						# no match found
  }

sub _ip2hex
  {
  # create a hex string from the IP (e.g. 1.2.3.4 => 01020304, 127.0.0.1 => 7f000001)
  my $ip = shift || '';

  my @parts = split /\./, $ip;
  my $hex = '';
  foreach (@parts)
    {
    $hex .= sprintf ("%02x", $_);
    }
  Math::BigInt->new('0x'. $hex);
  }

sub ip_matches
  {	   
  my ($check, $ip, $mask) = @_;

  # don't check if no mask or IP were specified
  return 1 if $mask eq '' or $mask eq '0.0.0.0' or $ip eq '' or $ip eq 'none';

  # create a hex string from the IP
  
  my $hex_ip = _ip2hex($ip);
  my $hex_check = _ip2hex($check);
  my $hex_mask = _ip2hex($mask);
  
  # and the check and the IP with the mask
  $hex_check &= $hex_mask;			# 1.2.3.4 & 255.255.255.0 => 1.2.3.0
  $hex_ip &= $hex_mask;				# 1.2.3.4 & 255.255.255.0 => 1.2.3.0

  ($hex_ip eq $hex_check) || 0;
  }

sub hash_pwd
  {
  my ($pwd) = shift;

  my $hash = Digest::MD5->new(); $hash->add($pwd); 
  $hash->hexdigest();
  }

1;

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Security - routines for authentication, checks and security

=head1 SYNOPSIS

	use Dicop::Security;

	$ip = '1.2.3.4';
	print "invalid ip $ip" unless Dicop::Security::valid_ip($ip);

=head1 REQUIRES

perl5.005, Exporter

=head1 EXPORTS

Exports nothing on default.

=head1 DESCRIPTION

This modules contains some routines to implement authentication, security
checks etc. These are in a seperate module to make testing and auditing easier.

=head1 METHODS

=head2 valid_ip

Return true if the given IP is a valid (at this time IPv4) IP.

=head2 valid_net

Return true if the given net is a valid (at this time IPv4) net. Examples:

	print "oups!\n" unless Dicop::Security::valid_net('1.2.3.4/32';

=head2 ip_is_in_net

Return true if the given IP is contained in the given net:
	
	print "oups!\n" unless
	  Dicop::Security::ip_is_in_net('1.2.3.4','1.2.3.4/32';

=head2 ip_matches

Return true if the given IP matches the given second IP and net mask.

	print "oups!\n" unless
	  Dicop::Security::ip_matches('1.2.3.5', '1.2.3.0','255.255.255.0');

A mask of C<255.255.255.255> dictates that the IP must match exactly, a mask of
C<255.255.255.0> means that the first 3 parts must match, and a mask of
C<0.0.0.0> means that every IP would match (regardless of second IP).

=head2 ip_is_in_net_list

Take one IP and a list of networks, and check whether the IP is in any
of the networks. Return 0 for IP is in one of the nets, 1 for IP is in none of
the nets, and <0 for error.

=head2 hash_pwd

	my $hash = hash_pwd($pwd);

Return MD5 hash of the given password.

=head2 valid_user

	if (valid_user(\@users, $user, $pwd)
	  {
	  # okay
	  }
	else
	  {
	  # user unknown or wrong password
	  }

Takes reference to a hash (containig user => pwdhash), a username and a
password hash. Returns 0 if the user exists in the list of users and the
password matches. Returns -1 if the user does not exist, and -2 if the user
exists, but the password hash does not match.

=head1 BUGS

None known yet.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See the file LICENSE or L<http://www.bsi.de/> for more information.

=cut
