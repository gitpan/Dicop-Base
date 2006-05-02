#############################################################################
# Dicop::Handler -- a generic request handler
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
use vars qw/@ISA $VERSION $BUILD $AUTOLOAD $NO_STDERR/;
$VERSION = '3.00';	# Current version of this package
$BUILD = $Dicop::Base::Build;
require  5.008001;	# requires this Perl version or later

use strict;

use Dicop::Base qw/write_file read_list random encode decode replace_templates/;
use Dicop::Request;
use Dicop::Request::Pattern;
use Dicop::Item qw/from_string/;
use Dicop::Config;
use Dicop::Security;
use Time::HiRes;
use File::Spec;

use Dicop::Event qw/lock unlock give_up crumble msg logger/;

use constant LOG_CRITICAL_ERRORS => 1;
use constant LOG_NON_CRITICAL_ERRORS => 4;

sub version { $VERSION; }
sub build { $BUILD; }

@ISA = qw/Dicop::Item/;

#############################################################################
# private, initialize self 

sub _construct_item
  {
  my ($self,$item,$args) = @_;

  $item->_construct($args);
   die ( crumble (ref($item) . " $item->{id} " . $item->{_error}) )
    if ($item->{_error} || '') ne '';
  }

sub _construct_file_names
  {
  # construct filenames for flush() from object list, plus {dir}
  my $self = shift;
  my $args = shift;
  my $cfg = shift;

  foreach my $what (@_)
    {
    # take args, if not defined, take cfg, if not defined, too, take default
    my $w = $what; $w =~ s/s$//; $w .= '_list';
    $self->{filenames}->{$what} =
      $args->{$w} || $cfg->{$what.'_list'} || "$what.lst";
    }

  # used by _flush()
  $self->{dir} = $args->{data_dir} || $cfg->{data_dir} || 'data';

  $self;
  }

sub _after_load
  {
  # override with code that finishes of loading data
  my $self = shift;

  $self;
  }

sub _after_config_read
  {
  # override and do here:
  my ($self,$cfg,$cfgdir,$cfgfile) = @_;

  # check config.
  # Dicop::Base::cfg_default( ... );
  # Dicop::Base::cfg_level($cfg, ...);
  }

sub _init
  {
  my ($self,$args) = @_;

  lock();                                               # lock data on disk
  $self->{filenames} = {};
  $self->{cfg_dir} = $args->{cfg_dir} || 'config';
  my $cfgdir = $self->{cfg_dir};
  my $cfgname = $args->{cfg} || 'server.cfg';

  my $cfgfile = File::Spec->catfile($cfgdir,$cfgname);
  give_up ("Global config file '$cfgfile' does not exist.")
    if (!-e $cfgfile);
  give_up ("Global config file '$cfgfile' is not a file.")
    if (!-f $cfgfile);

  print STDERR scalar localtime() . " Reading config from '$cfgfile'\n" unless $NO_STDERR;

  $self->{config} = Dicop::Config->new ($cfgfile);
  my $cfg = $self->{config};

  # we need log_level in log() etc
  Dicop::Base::cfg_level( $cfg, qw/log_level/);

  $self->{starttime} = Dicop::Base::cache_time();
  $self->{self} = $cfg->{self} || '/';
  $self->{last_flush} = 0;
  $self->{flush_time} = 0;
  $self->_clear_email_queue();
  $self->{style} = $cfg->{default_style} || 'default';
  $self->{connects} = 0;
  $self->{all_connects_time} = 0;
  $self->{last_connect_time} = 0;
  $self->{average_connect_time} = 0;

  # reset request counters
  $self->{requests} = {
    auth => 0, status => 0, errors => 0,
    report => { work => 0, test => 0 },
    request => { work => 0, test => 0, file => 0 }
    };

  $self->_after_config_read($cfg,$cfgdir,$cfgfile);
  $self->_load_messages();
  $self->_security_checks($cfgfile);
  $self->_load_request_patterns();
  $self->_load_object_definitions();

  ###########################################################################
  # read in data from external files/database
  $self->_load_data($args);
  # finish read in data and do some self-checks
  $self->_after_load($args);

  $self->{version} = $self->version();
  $self->{build} = $self->build();
  $self;
  }

sub _load_data
  {
  }

sub _load_messages
  {
  my $self = shift;
  my $cfg = $self->{config};

  my $msg_file = File::Spec->catfile($cfg->{msg_dir},$cfg->{language} || 'en', $cfg->{msg_file} || 'messages.txt');
  if (!-e $msg_file || !-f $msg_file)
    {
    $msg_file = File::Spec->catfile($cfg->{msg_dir},$cfg->{msg_file});
    }
  Dicop::Event::load_messages( $msg_file) or die("Could not load messages from $msg_file");
  }

sub _security_checks
  {
  my ($self,$cfgfile) = @_;

  my $cfg = $self->{config};
  foreach my $what (qw/admin stats status work/)
    {
    foreach my $d (qw/deny allow/)
      {
      # clean spaces
      $cfg->{"$d"."_$what"} = '' if !defined $cfg->{"$d"."_$what"};
      $cfg->{"$d"."_$what"} =~ s/\s+//g;

      # split into parts
      $self->{$d}->{$what} = [ split /\s*,\s*/, $cfg->{"$d"."_$what"} ];

      # die if critical security settings are not set
      die ( $self->log_msg( 803, $d."_$what", $cfgfile)) if (@{$self->{$d}->{$what}} == 0);
      # die if critical security settings are not valid
      foreach my $net (@{$self->{$d}->{$what}})
        {
        die( $self->log_msg (802, $d . "_$what", $net, $cfgfile, 0) )
         unless Dicop::Security::valid_net($net);
        }
      }
    }
  $self;
  }

sub _check_templates
  {
  # check that template files do exist
  my ($self, $type, $warn, @files) = @_;

  my $warnings = 0;
  my $cfg = $self->{config};
  foreach my $name (@files)
    {
    my $file = File::Spec->catfile( $cfg->{tpl_dir}, $cfg->{$type.'txt_dir'}, "$name.txt");
    if (!-e $file || !-f $file)
      {
      $warnings++;
      warn (" Error: $type template '$file' doesn't exist.\n")
        unless $warn;           # testsuite disables warnings
      }
    }
  $warnings;
  }

sub _load_object_definitions
  {
  my $self = shift;
  my $cfg = $self->{config};

  my $tpl_file = File::Spec->catfile($cfg->{def_dir}, $cfg->{objects_def_file} || 'objects.def');
  print STDERR scalar localtime() . " Reading object templates from '$tpl_file'\n" unless $NO_STDERR;
  Dicop::Item::_load_templates ( $tpl_file );
  $self;
  }

sub _load_request_patterns
  {
  my $self = shift;

  # load request.def file

  my $cfg = $self->{config};

  my $pattern_file = File::Spec->catfile($cfg->{def_dir}, $cfg->{patterns_file} || 'request.def');

  print STDERR scalar localtime() . " Reading request patterns from '$pattern_file'\n" unless $NO_STDERR;

  $self->{request_patterns} = [ Dicop::Item::from_file ( $pattern_file,
	'Dicop::Request::Pattern', ) ];

  foreach my $p (@{$self->{request_patterns}})
    {
    if (ref($p) ne 'Dicop::Request::Pattern')
      {
      require Carp; Carp::croak($p);
      }
    $p->_construct();
    # check for errors
    if ($p->error() ne '')
      {
      require Carp; Carp::croak($p->error());
      }
    }

  $self;
  }

{
  # override these in your subclass, and provide an AUTOLOAD stub like this:
  #sub AUTOLOAD
  #  {
  #  # set the right class for access to _method_foo()
  #  $Dicop::Handler::AUTOLOAD = $AUTOLOAD;
  #  Dicop::Handler::AUTOLOAD(@_);
  #  }

  sub _method_get_ok
    {
    my ($self,$method) = @_;
    0;	# always invalid, need override in subclass
    }
  sub _method_ok
    {
    my ($self,$method) = @_;
    0;	# always invalid, need override in subclass
    }
}

sub AUTOLOAD
  {
  my $name = $AUTOLOAD;

  $name =~ s/(.*):://;				# remove package name
  my $class = $1;
  no strict 'refs';

  if ($class->_method_get_ok($name))
    {
    my $type = $name;
    $type =~ s/^get_//; 
    $type = $class->name_from_type($type);	# get_proxy => proxies
    my $kind = $name; $kind =~ s/^get_//;	# get_job => job

    *{$AUTOLOAD} = sub {
      my $self = shift;
      my $id = shift || 0;
      my $no_error = shift;

      return $self->{$type}->{$id} if exists $self->{$type}->{$id};
      if (!$no_error)
        {
        crumble ("Illegal $kind id $id". join (' ',caller()) );
        $self->log_msg (430, $kind, $id );
        }
      return;
     };
    }
  elsif ($class->_method_ok($name))
    {
    *{$AUTOLOAD} = sub {
      my $self = shift;
      return scalar keys %{$self->{$name}};
    };
    }
  else
    {
    require Carp;
    Carp::confess ("Can't call $name, not a valid method");
    }
  &$AUTOLOAD;			# jump to generated method, uses @_
  }

sub _start_leak_report
  {
  my $self = shift;

  return unless defined $self->{_debug};
  
  $self->{_debug}->{leak_handle} = 1;
  $self->{_debug}->{leak_count} = Devel::Leak::NoteSV($self->{_debug}->{leak_handle});
  }

sub _end_leak_report
  {
  my $self = shift;

  return unless defined $self->{_debug};
  
  $self->{_debug}->{leak_count} = 
    Devel::Leak::CheckSV($self->{_debug}->{leak_handle}) -
    $self->{_debug}->{leak_count};
  
  my $d = $self->{_debug};
  my $cfg = $self->{config} || $self->{cfg};

  Dicop::Event::logger(File::Spec->catfile($cfg->{log_dir}, 'leak.log'),
      "$d->{leak_count} things seem to have leaked.") if $d->{leak_count} > 0;
  }

#############################################################################
sub name_from_type
  {
  # turn 'case' into 'cases' and 'proxy' into 'proxies' to allow access
  # to the storage where objects are stored, based on their type
  # (should have stored them just under their type...)
  my ($self,$type) = @_;

  my $name = $type; $name .= 's' unless $name =~ /s\z/; $name =~ s/ys$/ies/;
  $name;
  }

sub get_object
  { 
  # Generalized form to return object from { id => X, type => FOO }
  # overwrite it in your code!
  my $self = shift;

  undef;
  }

sub get_id_list
  {
  # return a list of all existing IDs from a given object type
  my ($self,$type) = @_;

  my $name = $self->name_from_type($type);

  my @array = sort keys %{$self->{$name}};
  @array;
  }

sub check
  {
  my $self = shift;
  # provide self-consistency checks
  # XXX TODO

  return;
  }

sub check_peer
  {
  # check IP/MASK against peeraddress
  my ($self,$peer,$ip,$mask,$client) = @_;

  return if Dicop::Security::ip_matches($peer, $ip,$mask);

  $self->log_msg(457, $peer, $client) . "\n";	# error
  }

sub flush
  {
  # check if we need to write changes to disk, if yes, call _flush_data()
  my ($self,$flush) = @_;

  # This does not track modified of single items, only of the main data
  # object. After flush the main data object is reset, and it will only be
  # set if one of the single objects is modified again.
  return unless $self->modified();	# do nothing if we are not modified

  my $now = Dicop::Base::time();
  if ((defined $flush) && ($self->{last_flush} != 0))
    {
    return if ($now - $self->{last_flush}) < $flush*60;
    }

  $now = Time::HiRes::time();
  $self->{last_flush} = $now;

  # flush now
  $self->_flush_data();
 
  $self->{flush_time} += Time::HiRes::time - $now;
  $self->modified(0);			# rest modified flag
  $self;
  }

sub _flush_data
  {
  # write changes to disk
  my $self = shift;

  # generic access
  my $storage = $self->{data_storage} || $self;

  foreach my $l (keys %{$self->{filenames}})
    {
    my $output = "";
    foreach my $id (sort { $a <=> $b } keys %{$storage->{$l}})
      {
      my $item = $storage->{$l}->{$id};
      $output .= $item->as_string();
      $item->flush($self->{dir});       # call flush() for each object
      }
    my $file = $self->{dir} . '/' . $self->{filenames}->{$l};
    write_file ($file,\$output);
    }
  $self;
  }

sub DESTROY
  {
  # destroy yourself, needs to break self-references
  my $self = shift;

  # the flush below is likely not to work due to random destroy order
  # on global destroy, so you need to  call DESTROY() or flush() explicitely
  # $self->flush();

  unlock();			# release lock on our data
  $self;
  }

sub default_request
  {
  'req0001=cmd_status;type_main';
  }

###############################################################################

sub type () { 'server'; }

sub _format_string
  {
  # Take a config key name part, append '_format', then take this config key
  # as format string. Then embed the given object and return final string
  my ($self, $cfg_key, $object) = @_;

  my $cfg = $self->{config};
  my $format = $cfg->{$cfg_key . '_format'};

  foreach my $key (keys %$object)
    {
    $format =~ s/##$key##/$object->{$key}/g;
    }    

  $format;
  }

sub convert_browser_request
  {
  # converts a hash with the submitted fields from a browser to a hash
  # containing (faked) normal requests
  my ($self, $form, $name) = @_;

  $name ||= 'submit'; 
  delete $form->{$name};
  # parameters are submitted by browser, and not yet in request format,
  # so convert them auf-der-fliege
  my $req = ""; my $auth_req = ""; my ($n);
  foreach $n (sort keys %$form)
    {
    my $var = encode($form->{$n});
    if ($n =~ /^auth-/)
      {
      my $m = $n; $m =~ s/^auth-//;
      $auth_req .= $m."_$var;";
      }
    else
      {
      $req .= $n."_$var;";
      } 
    }
  # convert additional params from button and override with them
  $req = $self->_convert_submit_button($name,$req) if $name =~ /^submit_/;

  $req =~ s/;$//; $auth_req =~ s/;$//;		# remove trailing ';' 
  my $f = { req0001 => $req, encoded => 1 };	# fake (encoded) request
  # if a normal submit button was pressed (no 'browse', 'refresh' etc) and we
  # had some 'auth-.*' fields, create a fake auth record
  if ($name !~ /submit_/ && $auth_req ne '')	
    {
    # convert the given username/password into a fake auth record and add it
    $f->{req0002} = "cmd_auth;version_1;arch_linux;id_1;$auth_req";
    }
  $f;
  }

sub _convert_submit_button
  {
  # take the name of the submit button and convert it into a request
  my ($self,$name,$req) = @_;

  $name =~ s/^submit_?//;

  if ($name =~ /(.+)=>(.*)/)
    {
    my ($rewrite, $params) = ($1, decode($2 || ''));

    my $form = '';
    foreach my $w (qw/cmd type id/)
      {
      next unless $params =~ /(^|;)$w\_([\w]+)/;
      next if !defined $2;
      my $f = $2;
      $req =~ s/(^|;)$w\_[\w+]+/$1/;
      $form .= $w . "_$f;";
      }
    # remove the style param
    $req =~ s/;?style\_[^;]*;?/;/; 
    $req =~ s/;+/;/g;				# ;; => ;
    $req =~ s/;+\z//; $req =~ s/^;+//;		# ^;foo => ^foo and foo;$ => foo$

    $form =~ s/;\z//;		# remove last ;

    $form = $form ? ';form_' . encode($form) : '';

    # avoid adding empty "params_" to req:
    my $r = "$rewrite$form";
    $r .= ";params_" . encode($req) if $req ne '';
    $req = $r;

    $req =~ s/;+/;/g;				# ;; => ;
    }
  else
    {
    print STDERR "Oops: Wrong submit buttin format: $name => $req\n";
    }

  $req;
  }

###############################################################################

sub parse_requests
  {
  # parse the form parameters, construct request and return as groups 
  my $self = shift;

  $self->{style} = $self->{config}->{default_style} || 'default';
  $self->{layout} = '' || '';
  my $form = Dicop::Base::parseFormArgs(@_);
  foreach my $field (keys %$form)
    {
    if ($field =~ /^submit/)
      {
      $form = $self->convert_browser_request($form,$field); last; 
      }
    }

  my (@auth,@others,@requests,@info,@forms,@errors);
  my $parsed = 0;
  my $max_requests = $self->{config}->{max_requests} || 256;
  foreach my $r (sort keys %$form)
    {
    last if $parsed++ > $max_requests;	# one more for error tracking
    next unless $r =~ /^req[0-9]{4}$/;	# ignore anything else

    my $re = Dicop::Request->new ( 
     id => $r, data => $form->{$r}, patterns => $self->{request_patterns} );

    if ($re->error())
      {
      push @errors, $re;
      }
    elsif ($re->is_request())
      {
      push @requests, $re;
      $self->{requests}->{request}->{$re->{type}} ++;
      }
    elsif ($re->is_auth())
      {
      # store auth record (count them, there can be only one)
      push @auth, $re;
      }
    elsif ($re->is_info())
      {
      push @info, $re;		# store info record
      }
    elsif ($re->is_form())
      {
      $self->{style} = $re->{style} if exists $re->{style};
      if ($self->{style} =~ /,/)
        {
        $self->{style} =~ s/,(.*)//;		# "Ice,clean" => "Ice"
        $self->{layout} = $1 || '';		# 'clean'
        }
      push @forms, $re;		# status pages, etc
      }
    else
      {
      my ($class,$t) = $self->other_request($re);
      push @others, $re;		# other requests
      $self->{requests}->{$class}->{$t} ++;
      }
    }
  $self->{requests}->{auth} += scalar @auth + scalar @info;
  $self->{requests}->{status} += scalar @forms;
  $self->{requests}->{error} += scalar @errors;
  (\@auth,\@info,\@others,\@requests,\@forms,\@errors); 
  }

sub other_request
  {
  my ($self,$re) = @_;

  ('other','unknown');
  }

sub _track_connect
  {
  my ($self,$time) = @_;

  $self->{all_connects_time} += $time; 
  $self->{last_connect_time} = $time; 
  $self->{average_connect_time} = $self->{all_connects_time} / ($self->{connects} || 1); 
  }

sub authenticate_user
  {
  # Find a user by his name, and then check that the hash from the given
  # password matches the stored hash value. Return 0 for okay, -1 for no such
  # user and -2 for wrong pwd.
  my ($self,$username,$pwd) = @_;

  my $user;
  my $users = $self->{ $self->name_from_type('user') };

  # find the user by his name
  foreach my $id (keys %$users)
    {
    if ($users->{$id}->{name} eq $username)
      {
      $user = $users->{$id}; last;
      }
    }
  return -1 if !defined $user;          # didn't find name in list?

  my $pwdhash = Dicop::Security::hash_pwd($user->{salt}.$pwd."\n");
  return 0 if $user->{pwdhash} eq $pwdhash;             # okay
  -2;                                                   # error, wrong pwd
  }

sub request_auth
  {
  # client/proxy connected, so authenticate and build initial response
  # if connect via proxy, check proxy and client, but return client
  my ($self,$auth_req, $info, $requests) = @_;

  # the auth request tells us who connected to us
  my $client = $self->check_auth_request($auth_req, 'req0000', 1);

  # build our response
  my $type = ucfirst($self->type()); my $name = $self->{config}->{name} || 'unknown';
  my $txt = "<PRE>\nreq0000 099 $type $name localtime ".localtime()."\n";

  # It must be a known client or proxy! If not return undef to signal error
  return (undef,$txt . $client) if !ref $client;

  # Check that in case we have info requests, the auth request comes from a
  # valid proxy
  if ((scalar @$info > 0) && (!$client->is_proxy()))
    {
    $txt .= $self->log_msg(456);        # info can only come from proxy
    return (undef,$txt);
    }

  my $req_map = {};
  # For each info request, figure out from the "for" field to which other
  # requests it applies. One proxy can send multiple info requests (for
  # multiple clients) plus a bunch of other requests, and each info request
  # carries in its "for" field the request numbers it applies to.
  foreach my $info_req (@$info)
    {
    # check that the info request is basically sound and the client exists
    my $client = $self->check_auth_request($info_req);

    # like: "for_req0001,req0002"
    # XXX TODO: check that "for_" doesn't list requests that do not exist
    my $for_hash = {};
    foreach my $f ( split /,/, $info_req->{for})
      {
      $for_hash->{$f} = 1;
      }

    if (ref($client))
      {
      # the info request is valid, so check to which others it applies
      foreach my $req (@$requests)
        {
        my $id = $req->request_id();
	$req_map->{$id} = $info_req if exists $for_hash->{$id};
        }
      }
    else
      {
      $txt .= $client;                          # append error msg

      # the info request is NOT valid, so mark all requests it applies to as
      # invalid, too
      # XXX TODO: should treat "for" as list of max. MAX_REQUESTS entries
      # like: "for_req0001,req0002"
      my $info_id = $info_req->{for};
      foreach my $req (@$requests)
        {
        my $id = $req->request_id();
	# store error message (no ref!)
	$req_map->{$id} = $client if exists $for_hash->{$id};
        #if ($id eq $info_id)
        #  {
        #  $req_map->{$id} = $client;        # store error message (no ref!)
        #  }
        }
      }
    }

  $type = 'client'; $type = 'proxy' if $client->is_proxy();
  $txt .= "req0000 099 Helo $type '$client->{name}'\n";

  ($client,$txt,$req_map);                      # okay
  }


sub handle_requests
  {
  # parse the form parameters, 
  # check it for beeing valid, and return answer or error
  my $self = shift;
  my $peer = shift || '0.0.0.0';
    
  lock('dicop_request_lock');
  Dicop::Base::cache_time();			# speed up
  my $req_time = Time::HiRes::time();	
	
  $self->{connects} ++;
  $self->{peeraddress} = $peer;			# who's connecting to us

  my ($auth,$info,$reports,$requests,$forms,$errors) = $self->parse_requests(@_);

  my $r = 'req0000 ';     
   
  # if status, only one request can be made at a time
  return $r.$self->log_msg(455,$forms->[0]->{cmd})
   # more than one status request? 
   if scalar @$forms > 1 ||
   # or one status request and something else?
      ((@$forms == 1) && (@$requests + @$reports + @$info > 0));

  # if cmd_form, no auth expected
  return $r.$self->log_msg(455,$forms->[0]->{cmd})
   if ((scalar @$forms == 1) && ($forms->[0]->{cmd} =~ /^(form|status)$/) &&
      (@$requests + @$reports + @$info + @$auth > 0));

  # too many requests or no requests at all?
  return $r.$self->log_msg(453) if ((@$requests + @$reports + @$forms + @$errors)  == 0); 
  return $r.$self->log_msg(454) 
   if ((@$requests + @$reports + @$info + @$auth + @$forms + @$errors)
    > $self->{config}->{max_requests});
  return $r.$self->log_msg(464) 
   if (scalar @$auth == 0) && (@$requests > 0);		# no auth at all?
  return $r.$self->log_msg(466) 
   if (scalar @$auth > 1);				# too many auth!
  
  # the auth request is always comming from the peer address connecting to us
  # either by browser, client-direct, or proxy, so overwrite it with the
  # correct one when coming not from browser
  $auth->[0]->{ip} = $peer if @$auth > 0;

  # find output title and type from first form request (there should be only one!)
  my ($title, $ctype) = ('','text');
  if (scalar @$forms > 0)
    {
    $title = ($self->{config}->{title} || 'DiCoP - ') . ($forms->[0]->title() || '');
    $ctype = $forms->[0]->output();
    }

  my $res = "";
  my $error;
  no strict qw'refs';
  my $handled = 0;	# number of handled requests
  my $client;		# client object of who is making request
  my $req_map = {};	# map request_id to the appropriate info requests (e.g.
			# the client they were sent for) in case of a proxy connect

  # if we found an auth request, check that it is valid, and in case of a
  # proxy, gather all the info requests and check them for basic validity, too.

  # authenticate the client/proxy by IP and check request, but not if it
  # came via direct browser contact for forms (in this case the IP is
  # authenticated otherwise) or erros (no auth for seeing an error msg)

  if ((@$auth == 1) && (@$forms == 0) && (@$errors == 0))
    {
    
    ($client,$res,$req_map) = 
      $self->request_auth($auth->[0], $info, [ @$requests, @$reports ] );

    return $res if !defined $client;		# error, couldn't authenticate
						# the client/proxy
    $handled += 1 + scalar @$info;		# handled so much requests
    }
  # else don't do anything, the IP is checked below

  # now for each request, check them and then handle them
  # first report work, then request new!
  foreach my $request (@$reports, @$requests, @$forms, @$errors)
    {
    $error = $request->error();
    if ($error eq '')
      {
      my $action = $request->class();
 
      return $r.$self->log_msg(462)
       if ($action !~ /^(admin|status|stats|work)$/); 	# something went wrong
      
      my $pwd = $request->auth();		# request needs authentication?

      # for this request, find the appropriate info request. 
      my $info = $req_map->{$request->request_id()} if $request->request_id();

      # If $req_map does not contain an valid entry for $req_map->{'req000X'},
      # then the request was invalid
      next if defined $info && !ref $info;

      # If there were no info requests, and it didn't come over a proxy, use the
      # auth request, otherwise deny. But do this check only for non-forms
      my $ip = $peer;					# default for forms
      if ($request->auth() != 0)
        {
        if (!ref($info) || !ref($client) || (ref($client) && !$client->is_proxy()))
          {
          $info = $auth->[0];
          }
        return $r.$self->log_msg(464)
          unless ref($info); 				# no auth found at all
        
        $ip = $info->{ip} || $peer;			# for anything else
        }
      else
        {
	# For requests that don't need an authentication, but the client did send
	# something in, use that. (This helps proxies while not disturbing the
	# rest of the code).
        $info = $auth->[0] if !defined $info && scalar @$auth > 0;	
        }

      $self->{peeraddress} = $ip;

      # check that the IP from the info/auth request is allowed and not denied
      # (The IP in the auth request is created by the server, not by the client
      # side - so it can be trusted. The IP in the info requests is created by
      # the proxy, not the clients, and we trust the proxies)

      my $denied = Dicop::Security::ip_is_in_net_list($ip, 
        $self->{deny}->{$action});
      return $r.$self->log_msg(413,$ip) unless $denied == 0; # ip is denied

      my $allowed = Dicop::Security::ip_is_in_net_list($ip, 
        $self->{allow}->{$action});
      return $r.$self->log_msg(413,$ip) unless $allowed > 0; # ip is not allowed

      # check password (if needed)
      if ($pwd != 0)
        {
        # this request needs a pwd, so check it (but not for sending out forms)
        return $r.$self->log_msg(469)
         unless $self->authenticate_user(
          decode($info->{user}||''),
	  decode($info->{pass}||'')) == 0;
        }
    
      # now try to really handle the single request
      
      # if the request needs to output HTML, read in the template
      if ($ctype =~ /^html/i)
	{
        if ($ctype eq "html-table")
	  {
          ($self->{tpl}, $self->{tplrow}) = $self->read_table_template($request->template_name());
	  }
	else
	  {
          $self->{tplrow} = undef;			# don't need a table
          $self->{tpl} = $self->read_template($request->template_name());
	  }
	last if !defined $self->{tpl};		# error reading tpl?
        $self->_include_form($self->{tpl}, $request);
	}

      my $method = $request->{cmd} . '_' . ($request->{type} || '');
      if (!$self->can($method))
        {
        # if 'del_foo' does not exist, try 'del'
        $method = $request->{cmd};
	# fallback: 'cmd_form;type_job' => form() doesn't exist, try status()
        $method = 'status' if !$self->can($method);
        }
      my $rc = $self->$method ($request,$client,$info);

      # handler did encounter any error?
      return unless defined $rc;
      
      $rc = $$rc if ref($rc); $res .= $rc; $handled++;
      }
    else
      {
      $title = 'Request error';	$res .= $error;	# for status errors
      }
    } # end foreach request

  if ($ctype =~ /html/i && $handled > 0)
    {
    $res = $self->html_header() . $res . $self->html_footer();
    $res =~ s/##base-version##/$Dicop::Base::VERSION/g;
    $res =~ s/##base-build##/$Dicop::Base::BUILD/g;
    $res =~ s/##uptime##/$self->uptime();/eg;

    $res =~ s/##os##/$self->{config}->{os} || $^O/eg;
    $res =~ s/##name##/$self->{config}->{name} || 'unknown'/eg;

    foreach my $i (qw/ self load connects style version build /)
      {
      $res =~ s/##$i##/$self->{$i}/g;
      }
    foreach my $i (qw/ last_connect_time all_connects_time average_connect_time /)
      {
      my $time = sprintf("%.4f", $self->{$i});
      $res =~ s/##$i##/$time/g;
      }
    my $r = 0;
    foreach my $re (qw/report request status auth/)
      {
      if (ref($self->{requests}->{$re}) eq 'HASH')
        {
        my $cnt2 = 0;
        foreach my $t (qw/work test/)
          {
          $res =~ s/##$re[_]$t[_]requests##/$self->{requests}->{$re}->{$t}/g;
          $cnt2 += $self->{requests}->{$re}->{$t} || 0;
          }
        $res =~ s/##$re[_]requests##/$cnt2/g;
        $r += $cnt2;
        }
      else
        {
        $res =~ s/##$re[_]requests##/$self->{requests}->{$re}/g;
        $r += $self->{requests}->{$re} || 0;
        }
      }
    $res =~ s/##requests##/$r/g;

    my $type = $self->type() || 'unknown';
    $res =~ s/##servertype##/$type/g;

    my $style = $self->{style};
    $style .= ",$self->{layout}" if $self->{layout};
    $res =~
     s/##self(.*?)_(.*?)##/$self->{self}\?req0001=cmd_$1;type_$2;style_$style/g;

    if (@$forms == 1)
      {
      my $r = $forms->[0]->as_request_string();
      $res =~
       s/##selfreq##/$self->{self}\?$r/g;
      }

    my $rem = $ENV->{REMOTE_ADDR} || '127.0.0.1';  
    $res =~ s/##remoteaddr##/$rem/g;  
    $res =~ s/##localtime##/localtime($req_time)/eg;
    $res =~ s/##title##/$title/g;

    $req_time = sprintf("%.3f",Time::HiRes::time() - $req_time);
    $res =~ s/##handletime##/$req_time/g;
    $req_time = Dicop::Base::ago(Dicop::Base::time() - $self->{starttime});
    $res =~ s/##runningtime##/$req_time/g;
    $res =~ s/##user##/$self->{config}->{user}/g;
    $res =~ s/##group##/$self->{config}->{group}/g;
    $req_time = 'not chrooted';
    $req_time = 'chrooted' if ($self->{config}->{chroot} || '') ne '';
    $res =~ s/##chroot##/$req_time/g;

    $req_time = 'never';
    $req_time = scalar localtime($self->{last_flush}) if $self->{last_flush};
    $res =~ s/##last_flush##/$req_time/g;
    my $f = sprintf("%.2f",$self->{flush_time});
    $res =~ s/##flush_time##/$f/g;
    $req_time = 'unknown time';
    $req_time = Dicop::Base::ago(int(Dicop::Base::time() - $self->{last_flush}))
      if $self->{last_flush};
    $res =~ s/##last_flush_ago##/$req_time/g;
    $self->finish_html_request(\$res);		# replace other templates etc
    }
  $self->finish_connect(\$res); 		# replace other templates etc

  unlock('dicop_request_lock');
  \$res;
  }

sub finish_html_request
  {
  my ($self,$result) = @_;
  }

sub finish_connect
  {
  my ($self,$result) = @_;

  $result;
  }

sub pre_connect
  {
  my ($self,$peer,$params) = @_;
  }

sub log_msg
  {
  # return a message with inlined parameters, and if code is an error code,
  # log the message
  my $self = shift; my $code = shift;

  my $txt = msg($code,@_);
  if (($code >= 300) || ($code < 100))
    {
    my $cfg = $self->{config};
    my $ip = $self->{peeraddress} || "[unknown]";
    my $log = $cfg->{error_log};
    $log = $cfg->{server_log} if $code >= 750 && $code < 800;
    my $msg = "$ip $txt";
    Dicop::Event::logger(File::Spec->catfile($cfg->{log_dir},$log),
      $msg)
     if (($self->{config}->{log_level} & LOG_CRITICAL_ERRORS) != 0);
    $self->{last_error} = $msg;
    }
  $txt;   
  }

sub _replace_mail_templates
  {
  # my ($self,$message, $job,$chunk,$client,$result) = @_;
  # $$message =~ s/..../.../; # etc
  # $self;
  }

sub email
  {
  # prepare email based on a template and further info, then place it
  # in the send queue
  my ($self,$type, $cc, @params) = @_;
  my $c = $self->{config};

  # read in message and replace all tags
  my $message = '';
  if ($type ne 'none')				# for testsuite
    {
    $message = $self->read_template( 
      File::Spec->catfile( $c->{mailtxt_dir}, "$type.txt") );
    return if !defined $message;		# error
    $message = $$message;
    }
  my $time = scalar localtime( Dicop::Base::time() );
  $message =~ s/##localtime##/$time/g;
  $message =~ s/##peeraddress##/$self->{peeraddress}/g;

  # replace mail text templates here
  $self->_replace_mail_templates(\$message,@params);

  # now convert it to a hash for Dicop::Mail
  my @lines = split /\n/,$message;
  my $header = 1; my %mail; my $msg = ""; my $header_text = "";
  foreach my $line (@lines)
    {
    next if $line =~ /^#/;		# strip comments
    foreach my $type (qw/ from to errors/)
      {
      $line =~ s/##mail_$type##/$c->{'mail_' . $type} || ''/eg;
      }
    # are we still in the header?
    if ($header == 1)
      {
      $header = 0, next if $line =~ /^\s*$/;	# switch to body?
      $header_text .= "$line\n";
      $line =~ /^(.*?):(.*)$/;			# find Field: and data
      $mail{$1} = $2 if ($1||''ne'')&&($2||''ne''); # if both parts are there
      next;
      }
    $msg .= "$line\n";
    }
  # provide some defaults 
  delete $mail{body}; delete $mail{text}; 	# Justin Case
  $mail{message} = $msg;
  $mail{header} = $header_text;
  $mail{server} = $c->{mail_server} || 'localhost';
  $mail{smtp} = $mail{server};
  $mail{cc} = $cc if $cc;
  $mail{written} = 0;					# only once

  push @{$self->{email_queue}}, \%mail;	# put into queue
  }

sub _clear_email_queue
  {
  # delete anything in the email send queue (mainly used by testsuite)
  my $self = shift;

  $self->{email_queue} = [];
  $self;
  }

sub html_header
  {
  my $self = shift;

  ${ $self->read_template("header.txt") };
  }

sub html_footer
  {
  my $self = shift;
  ${ $self->read_template("footer.txt") };
  }

sub find_template
  {
  # Try to find a template file, first looking at the style
  my ($self,$file) = @_;

  warn ("Template file not defined or empty: ") unless $file;

  # try override in styles dir first 
  my $rfile = File::Spec->catfile($self->{config}->{tpl_dir} || 'tpl',
				  'styles',
				  $self->{style} || '',
				  $file);
  # doesn't exist? So use base template
  if (!-f $rfile)
    { 
    $rfile = File::Spec->catfile($self->{config}->{tpl_dir} || 'tpl' ,$file);
    }
  $rfile;
  }

sub _read_template
  {
  my ($self,$file,$include,$params) = @_;

  my $txt = Dicop::Base::read_file($file);
  if (!defined $txt)
    {
    # could not read?
    warn "Couldn't read file '$file': $!";
    }
  else
    {
    $self->_include_template($txt,$include,$params);
    }
  $txt;
  }

sub read_template
  {
  # read a template file from the template dir, honouring styles
  # inside the template, include file via ##include_filename.inc##
  my ($self,$file,$include,$params) = @_;

  warn ("File not defined or empty") unless $file;
 
  my $layout = $self->{layout} || 'default';
  $file =~ s/__LAYOUT__/\/styles\/$layout/;

  my $rfile = $self->find_template($file); 

  $self->_read_template($rfile,$include,$params);
  }

sub _include_template
  {
  # find ##include_filename.inc## inside a template and include the file
  # there. If $include is defined, will not include any further templates
  # to avoid recursion.
  my ($self,$txt,$include,$params) = @_;

  return $txt unless ref($txt);
  if (defined $params && $params ne '')
    {
    my @params = split /:/,$params;
    my $p = 0;
    foreach my $par (@params)
      {
      $$txt =~ s/##param$p##/$par/g; $p++;
      }
    }
  if (!defined $include)
    {
    # If no error, include files, but don't nest including
    # For security reasons we only include files containing letters, '_' and
    # ending in '.inc'
    $$txt =~ s/##include_(\w+?\.inc):?([:\w\s.,;-]*)##/my $t = $self->read_template($1,'no_recurse',$2) || 'template file not found: $!'; $t = $$t if ref($t); $t;/ieg;
    }

  $txt;
  }

sub class_from_type
  {
  my ($self,$type) = @_;

  # turn "foo" into 'Dicop::Handler::Foo' (or equivalent)
  my $class = ref($self) . '::' . ucfirst($type);
  $class;
  }

sub _include_form
  {
  # find ##edit-object-fields## and replace it with a list of entry fields
  # to edit this object (or add an object). This is basically an auto-form
  # generator.
  my ($self,$txt,$req) = @_;

  return unless ref($txt) && $$txt =~ /##(edit|add)-object-fields##/;
  my $form = $1 || 'edit';

  # guard against wrong usage:
  if (!(defined $req->{id} && defined $req->{type} && $form eq 'edit')
    &&
     !(defined $req->{type} && $form eq 'add'))
    {
    return;
    }

  # the name of the form we need to return to after selecting a file/dir
  my $formname = '';
  $formname = 'cmd_' . $req->{cmd} if defined $req->{cmd};
  $formname .= ';type_' . $req->{type} if defined $req->{type};
  $formname .= ';id_' . $req->{id} if defined $req->{id};
  # XXX TODO: for chunks: that shouldn't be hardcoded
  # instead if should probably append the "carry" list from Template class
  #$formname .= ';job_' . $req->{job} if defined $req->{job};

  $$txt =~ s/##type##/$req->{type}/g;
  $$txt =~ s/##cmd##/$req->{cmd}/g;
  $$txt =~ s/##id##/$req->{id}||''/eg;

  # build list
  my $list = '';

  my ($tpl,$item);
  if ($form eq 'edit')
    {
    $item = $self->get_object($req);
    return unless defined $item && ref($item);
    $tpl = $item->template(); 
    }
  else
    {
    my $class = $self->class_from_type($req->{type});
    $tpl = Dicop::Item::template($class); 
    }

  # parse the passed params and use them to override the values so that
  # former user changes are presevered
  my $params = {};
  my @pairs = split /;/, decode($req->{params} ||'');
  foreach my $pair (@pairs)
    {
    next if ($pair || '') eq '';
    my ($name,$val) = split /_/, $pair;
    $params->{$name} = decode($val || '');
    }

  # in addition, if targetfield and targetvalue exist, use them to overwrite
  if (($req->{targetname} || '') ne '')
    {
    $params->{ $req->{targetname} } = decode($req->{targetvalue} || '');
    }

  my $tpls = {};

  return crumble ("Cannot generate edit form - no template defined for object type $req->{type}!")
    unless defined $tpl;

  # get all fields necc. for this form
  my @field_names; my $method = $form . 'able_fields';
  @field_names = $tpl->$method();

  my @fields;
  # generate list with template-fields from names
  foreach my $name (@field_names)
    {
    push @fields, [ $name, $tpl->field($name) ];
    }

  my $rank = $form . 'rank';

  # sort by '(edit|add)rank' (or editrank), then by name
  @fields = sort {
     my $c = $a->[1]->{$rank} || $a->[1]->{editrank} || 10000;
     my $d = $b->[1]->{$rank} || $b->[1]->{editrank} || 10000;
     $c <=> $d or $a->[0] cmp $b->[0]; } @fields;

# left_indend = max_indend + 1; right_indend = left_indend - field_indend; filler = field_indend;

# sample for one normal field: (max_indend = 0)
#  <tr>
#  <td colspan="1" align="right">
#    MylongField:
#  </td>
#  <td colspan="1">
#    <input type="text" value="Fooo" name="foo" size="64">
#  </td>
#  </tr>

# sample for one normal and one indended field: (max_indend = 1);
#  <tr>
#  <td colspan="2" align="right">
#    MylongField:
#  </td>
#  <td colspan="2">
#    <input type="text" value="Fooo" name="foo" size="64">
#  </td>
#  </tr>
#
#  <tr>
#  <td class="filler"></td>
#  <td colspan="2" align="right">
#    Field:
#  </td>
#  <td colspan="1">
#    <input type="text" value="Fooo" name="foo">
#  </td>
#  </tr>

# sample for one normal, one indend by one and one indended by two:
# (max_indend = 2)
#  <tr>
#  <td colspan="3" align="right">
#    MylongField:
#  </td>
#  <td colspan="3">
#    <input type="text" value="Fooo" name="foo" size="64">
#  </td>
#  </tr>
#
#  <tr>
#  <td class="filler"></td>
#  <td colspan="3" align="right">
#    Field:
#  </td>
#  <td colspan="2">
#    <input type="text" value="Fooo" name="foo">
#  </td>
#  </tr>
#
#  <tr>
#  <td class="filler"></td>
#  <td class="filler"></td>
#  <td colspan="3" align="right">
#    Mygoeshere:
#  </td>
#  <td colspan="1">
#    <input type="text" value="Fooo" name="foo" size=54>
#  </td>
#  </tr>

# and so on.
  
  # go over all fields and calculate the maximum indend
  my $max_indend = 0;
  for my $field (@fields)
    {
    my $field_indend = abs($field->[1]->{$form.'indend'} || $field->[1]->{editindend} || 0);
    $max_indend = $field_indend if $field_indend > $max_indend;
    }
  my $left_indend = $max_indend + 1;

  # the while loop allows us to push more fields at the end when we encounter extrafields
  while (scalar @fields > 0)
    {
    my $f = shift @fields;
    my $field = $f->[1]; my $name = $f->[0];
    # get the field type
    my $type = $field->{type};
    # get the indend for the current field
    my $field_indend = abs($field->{$form.'indend'} || $field->{editindend} || 0);
    my $right_indend = $left_indend - $field_indend;

    my @valid = ();

    # if we have editoption or addoption hashes, add them first
    if (ref($field->{$form.'option'}) eq 'HASH')
      {
      my $n = $field->{$form.'option'};
      for my $key (sort keys %$n)
        {
	push @valid, [ $key, $n->{$key} ];
        }
      }

    # if type eq 'case_id' then select all cases and include as list
    if ($type =~ /(^[a-zA-Z]+)_/)
      {
      my $id_type = $1;
      $type =~ s/^[a-zA-Z]+_//;	# case_id => id

      # type_simple => 'type', 'simple'
      my ($filter_type,$filter) = split /_/, ($field->{filter} || '');
      $filter_type ||= ''; $filter ||= '';

      my @ids = $self->get_id_list($id_type);
      my $method = 'get_' . $id_type;
      foreach my $id (sort { $a <=> $b } @ids)
	{
	my $item = $self->$method($id);

	# if we need to filter items out, do so now
	if ($filter_type ne '')
	  {
	  # skip that item if filter doesn't match
	  next if $item->{$filter_type} ne $filter;
	  }

	my $name = $item->{name} || '';
	my $des = $item->{description} || '';
        if ($name ne '' && $des ne '')
	  {
	  $name = "$name ($des)";
          }
        else
          {
	  $name = $name || $des || $id;
          }
	push @valid, [ $id, $name ];
	}
      }
    elsif (exists $field->{valid})
      {
      # if the valid field exists, use it to build a list of valid values
      my $v = $field->{valid};

      # no ref => valid points to the method to get the list (as array or hash)
      if (!ref($v))
	{
	die ("Cannot get list of valid items via '$v': no such method")
	  unless $self->can($v);
	$v = $self->$v();		# '$v' should return a list of valid items
	}

      # if already array, use them in that order
      if (ref($v) eq 'ARRAY')
	{
	for (my $i = 0; $i < scalar @$v; $i += 3)
	  {
	  push @valid, [ $v->[$i+1], $v->[$i+2], $v->[$i] ];
	  }
	}
      # otherwise build a sorted list from hash
      else
        {
        foreach my $k (sort keys %$v)
	  {
	  push @valid, [ $k, $v->{$k} ];
	  }
        }
      }
    # sort the list of valid things?
    if ($field->{sort})
      {
      @valid = sort { $a->[1] cmp $b->[1] or $a->[0] <=> $b->[0] } @valid;
      }

    # build from this a template file name
    my $sel = $field->{selector} || $type;
    $sel .= '_refresh' if $field->{refresh};

    my $file = "editfield_$sel.inc";

    # if we have a list of known valid values, use a dropdown box instead
    if (scalar @valid != 0)
      {
      my $sel = $field->{selector};
      if (ref $field->{valid} eq 'ARRAY')
	{
	$sel = $field->{selector} || 'check';
	}
      else
	{
	$sel = $field->{selector} || 'select';
	}
      $sel .= '_refresh' if $field->{refresh};

      $file = "editfield_$sel.inc";

      my ($txt,$tpl) = $self->read_table_template($file);
      # for each valid item, include in list
      my $select = '';

      my $current = ''; $current = $item->get($name) || '' if $form eq 'edit';
      # use supplied params to overwrite values
      $current = $params->{$name} if exists $params->{$name};

      foreach my $v (@valid)
	{
	my $t = $tpl; chomp($t);		# remove \n
	$t =~ s/##validvalue##/$v->[0]/g;
	$t =~ s/##validname##/$v->[1]/g;

	# for list box selector
	my $s = ''; 
	if ($v->[0] eq $current)
	  {
	  $s = ' selected';
          # for the current item, include extra fields
          my $class = $field->{type}; $class =~ s/_id$//;
          my $item = $self->get_object( { id => $v->[0], type => $class }, 'noerror' );
          my @extras;
          @extras = @{$item->{extrafields}} if ref($item) && ref($item->{extrafields}) eq 'ARRAY';
	  my $i = 0;
	  foreach my $ef (@extras)
	    {
	    push @fields, [ "extra$i", { def => '', name => ucfirst($ef), type => 'string', help => "Enter the $ef." } ];
	    $i++;
	    }
          }
	$t =~ s/##selected##/$s/g;

	$s = $v->[2] ? '' : ' checked';		# select lowest for add as default
	# for checkbox lists
	if ($form eq 'edit')
	  {
	  $s = '';
	  my $bit = $v->[2];				# get the bit to select
	  # XXX TODO: get field from item, extract bit and then set $s accordingly
	  }
        $t =~ s/##checkedvalue##/$s/g;

	$select .= $t;
	}
 
      $$txt =~ s/##table##/$select/;
      # mark file as loaded (it will be loaded again for the next dropdown box)
      $tpls->{$file} = $$txt;
      }

    # load this as template if not already loaded
    if (!exists $tpls->{$file})
      {
      my $t = $self->find_template($file);
      if (!-f $t)
        {
        # fallback to 'string'
        $t = $self->find_template('editfield_string.inc');
	}
      $t = $self->_read_template($t);
      $tpls->{$file} = $$t if ref $t;
      }

    my $edit_field = $tpls->{$file} || '';	# '' if we couldn't load it
    # modify the read-in template field
    $edit_field =~ s/##fieldname##/$name/g;
    $edit_field =~ s/##formname##/$formname/g;
    $edit_field =~ s/##style##/$self->{style}/g;
    
    $edit_field =~ s/##indend##/$left_indend/g;
    $edit_field =~ s/##-indend##/$right_indend/g;
    $edit_field =~ s/##indend(\+\d*)##/$left_indend + ($1||0)/eg;

    if ($field_indend > 0)
      {
      if (!defined $tpls->{'edit_indend.inc'})
	{
        my $t = $self->find_template('edit_indend.inc');
        $t = $self->_read_template($t);
        $tpls->{'edit_indend.inc'} = $$t if ref $t;
        }

      my $filler = $tpls->{'edit_indend.inc'};
      if (defined $filler)
        {
        my $table_code = $filler x $field_indend;
        $edit_field =~ s/##indend_filler##/$table_code/g;
        }
      # for classnames like "editfieldname" and "editfieldname1"
      $edit_field =~ s/##fieldindend##/$field_indend/g;
      }
    else
      {
      $edit_field =~ s/##indend_filler##//g;
      # for classnames like "editfieldname" and "editfieldname1"
      $edit_field =~ s/##fieldindend##//g;
      }
      
    $edit_field =~ s/##field(\w+)##/$field->{$1}||''/eg;
    # the name that appears in front of the edit field:
    my $n = $field->{name} || ucfirst($name);
    $n =~ s/\s/&nbsp;/g;				# ' ' => '&nbsp;'
    $edit_field =~ s/##field##/$n/g;
    if ($form eq 'edit')
      {
      $n = '';
      # pwd fields are virtual, so do not fetch them from the object
      $n = $item->get_as_string($name) || '' if $type ne 'pwd';
      # booleans are special
      $n = $item->{$name} ? 1 : 0 if $type eq 'bool';
      }
    else
      {
      $n = $field->{def}; $n = '' unless defined $n;
      }
    # use supplied params to overwrite values
    $n = $params->{$name} if exists $params->{$name};

    # plain text for edit boxes
    $edit_field =~ s/##value##/$n/g;
    # encoded for request params
    $n = encode($n);
    $edit_field =~ s/##safevalue##/$n/g;
    $n = $n ? 'checked' : ''; $edit_field =~ s/##checkedvalue##/$n/g;
    $n = $field->{editlen} || $field->{minlen} || 80;
    $n = $field->{maxlen} if $field->{maxlen} && $n > $field->{maxlen};
    $edit_field =~ s/##size##/$n/g;

    $list .= $edit_field;
    } # end for all fields
  
  my $carry = '';

  if ($item)
    {
    # get the 'carry' fields from the request pattern
    my @carry = $req->carry();
    foreach my $c (@carry)
      {
      # fetch the requested field
      my ($i,$f) = split /_/, $c;
      my $field = $item->{$i};
      $field = $field->{$f} if ref($field) && exists ($field->{$f});
      $carry .= "<input type=\"hidden\" name=\"$i\" value=\"$field\">\n"
        if $field;
      }
    }
 
  $$txt =~ s/##carry##/$carry/g;

  # insert list into template
  $$txt =~ s/##(add|edit)-object-fields##/$list/;
  
  # insert description and help text from template
  foreach my $key (qw/description help include/)
    {
    my $text = $tpl->$key();
    $$txt =~ s/##object-template-$key##/$text/g;
    }

  # replace eventual ##include...## by the template contents
  $self->_include_template($txt);

  # insert potential <select><option...></select> lists
  $self->_option_list($txt);

  # done
  $txt;
  }

sub read_table_template
  {
  # read a table template file from the template dir, honouring styles
  # inside the template, include file via ##include_filename.inc##

  my ($self,$file,$include,$params) = @_;

  # try override in styles dir first 
  my $rfile = File::Spec->catfile(
   $self->{config}->{tpl_dir} || '', 'styles', $self->{style} || '', $file);
  # doesn't exist? So use base template
  if (!-f $rfile)
    { 
    $rfile = File::Spec->catfile( $self->{config}->{tpl_dir} || '', $file);
    }
  my ($txt,$tpl) = Dicop::Base::read_table_template($rfile);
  $self->_include_template($txt,$include,$params);

  ($txt,$tpl);
  }

sub request_file
  {
  # client requested a file, so send it to him
  my ($self,$req,$client,$info) = @_;

  my ($proxy,$msg);			# if client came via proxy
  ($proxy,$client,$msg) = $self->_client_from_info($req,$client,$info);
  return $msg if defined $msg;		# error

  my $r = $req->{_id} . ' ';

  my $file = decode($req->{name});
  $file =~ s/^\.\///;                           # remove a leadin ./
  # check for filename with illegal formats

  return $r . $self->log_msg(411,$file) . "\n"
   if $file !~ /^[a-zA-Z0-9\/._\s:,\(\)=+-]+$/; # unclean file name
  return $r . $self->log_msg(411,$file) . "\n"
   if $file =~ /\.\./;                          # .. is not allowed
  return $r . $self->log_msg(411,$file) . "\n"
   unless $file =~ /^(worker|target)\//;        # only these two are okay
                                                # ./worker or ./target are ok

  # check if file exists (unless not requested - like from Proxy)
  if (!defined $self->{no_file_check})
    {
    return $r . $self->log_msg(412,$file) . "\n"
     unless -e $file && -f $file;                 # exists and is regular file?
    }

  # return to client an URL to the file in question
  if (ref($self->{config}->{file_server}) eq 'ARRAY')
    {
    my $res = '';
    # sort the sent-back URLs by matching them against the client's IP
    # address to allow client to download from near servers first?
    foreach my $server (sort { $a cmp $b } @{$self->{config}->{file_server}})
      {
      $res .= $r."200 $server$file\n";
      }
    return $res;
    }
  $r . "200 $self->{config}->{file_server}$file\n";
  }
  
sub _status_sort
  {
  # used by status() to sort the objects, can be overriden in subclass
  my ($self, $req) = @_;

  # default sub
  my $sort_up = sub { $a <=> $b };

  # get the pattern
  return $sort_up unless ref($req);
  my ($sort_dir, $sort_by) = $req->sort_order();

  return $sort_up if $sort_dir eq 'up' and $sort_by eq 'id';

  my $sort_down = sub { $b <=> $a };
  return $sort_down if $sort_dir eq 'down' and $sort_by eq 'id';

  # sort on something else than ID (sort_by is 'id<=>', 'name', 'rank<=>' etc)
   
  $sort_dir =~ s/(str)\z//;				# upstr, downstr => up,down
  my $str = $1 ? 1 : 0;
  $sort_dir =~ tr/a-z//cd; $sort_by =~ tr/a-z//cd;	# lower case only
  my $sort;
  my $type = $self->name_from_type($req->{type});
  my $d = $self->{data_storage} || $self; $d = $d->{$type};

  if ($sort_dir eq 'up')
    {
    if ($str)
      {
      $sort = sub {
        my $aa = $d->{$a}; my $bb = $d->{$b};				# turn ID into item
        $aa->{$sort_by} cmp $bb->{$sort_by} or $aa->{id} <=> $bb->{id} 	# sort statement
        };
      }
    else
      {
      $sort = sub {
        my $aa = $d->{$a}; my $bb = $d->{$b};				# turn ID into item
        $aa->{$sort_by} <=> $bb->{$sort_by} or $aa->{id} <=> $bb->{id} 	# sort statement
        };
      }
    }
  else
    {
    if ($str)
      {
      $sort = sub {
        my $aa = $d->{$b}; my $bb = $d->{$a};				# turn ID into item
        $aa->{$sort_by} cmp $bb->{$sort_by} or $aa->{id} <=> $bb->{id} 	# sort statement
        };
      }
    else
      {
      $sort = sub {
        my $aa = $d->{$b}; my $bb = $d->{$a};				# turn ID into item
        $aa->{$sort_by} <=> $bb->{$sort_by} or $aa->{id} <=> $bb->{id} 	# sort statement
        };
      }
    }
  $sort;			# sort-routine
  }

sub status
  {
  # create a (sorted on id) table of some things
  my ($self,$req) = @_;

  if (defined $self->{tplrow})
    {
    my $type = $req->{type};
    my $hl = $req->{id} || 0;
    my $res = $self->_gen_table( $self->{tpl}, $self->{tplrow}, $hl, [ $type ], $self->_status_sort($req));
    replace_templates( $res, $req);
    return $res;
    }

  if (defined $req && defined $req->{type})
    {
    # get the item from the request ID if defined TYPE and ID
    if ($req->{type} && $req->{id})
      {
      my $method = 'get_' . $req->{type};
      my $item = $self->get_object($req);
      if (ref $item)
        {
        replace_templates( $self->{tpl}, $item);
        # replace ##FOO_list## be $item->FOO_list()
        ${$self->{tpl}} =~ s/(##([a-z]+_list)##)/$self->can($2) ? $self->$2($item,$req) : $1;/eg;
        }
      }
    elsif ($req->{type} =~ /s\z/)
      {
      # replace ##FOO_list## be $self->FOO_list(undef,$req);
      ${$self->{tpl}} =~ s/(##([a-z]+_list)##)/$self->can($2) ? $self->$2(undef,$req) : $1;/eg;
      }

    replace_templates( $self->{tpl}, $req);

    my $rstr = $req->as_request_string();
    $rstr =~ s/req\d\d\d\d=//;			# remove req0001
    $rstr = encode(encode($rstr));
    ${$self->{tpl}} =~ s/##reqparams##/$rstr/g;
    }

  $self->{tpl};
  }

sub _gen_table
  {
  # an even more generic routine to generate as HTML output a table listing
  my ($self,$txt,$tpl,$highlight,$ids,$sort,$filter) = @_;

  my $list = ""; my ($line,$i);
  my $item_nr = 0;
  my $trclass = 'odd'; my $tr = 0;

  # general access to items/data
  my $data_storage = $self->{data_storage} || $self;

  foreach my $group (@$ids)
    {
    my $items;
    if (ref($group) eq 'HASH')
      {
      $items = $group->{ids};
      $group = $group->{type};
      }
    else
      {
      $items = $data_storage->{$group};
      }
    my $groupname = $group;
    $groupname =~ s/ies$/y/;    # proxies => proxy
    $groupname =~ s/s$//;       # clients => client
    
    my @keys = sort $sort keys %$items;

    foreach my $item (@keys)
      {
      # take either the given ID, or the given object
      $i = $item; $i = $data_storage->{$group}->{$item} unless ref($i);

      # filter out this item?
      next if $filter && exists $filter->{on}->{ $item->{ $filter->{type} } };
 
      $item_nr++;

      $tr == 0 ? ($trclass = '') : ($trclass = 'odd');
      $trclass = 'highlight' if $highlight eq $i->{id};
      $trclass = " class=\"$trclass\"" if $trclass ne '';
      $tr = 1 - $tr;

      $line = $tpl;
      $line =~ s/<td>/<td$trclass>/ig;
      $line =~ s/<td align=/<td$trclass align=/ig;
      $line =~ s/##object_group##/$group/g;
      $line =~ s/##rank##/$item_nr/g;

      my $action = "<a href=\"##selfconfirm_$groupname##;id_$i->{id}\">del</a>";
      my $g = $group;
      $g = $groupname if ($group =~ /clients|jobs/);
      $action .= "&nbsp;<a href=\"##selfstatus_$g##;id_$i->{id}\">view</a>";

      $line =~ s/##actionlist##/$action/;
      # must go over item, not line, since line can contain ##self## etc
      my @keys = keys %$i; @keys = $i->fields() if $i->can('fields');
      foreach my $k (@keys)
        {
        $line =~ s/##($k.*?)##/$i->get_as_string($1) || ''/eg;
        }
      $list .= $line;
      }
    }
  $$txt =~ s/##table##/$list/;
  $txt;
  }

sub status_style
  {
  # create a sorted table of styles
  my $self = shift;
  my $req = shift;

  my ($txt,$tpl) = ($self->{tpl},$self->{tplrow});

  my $style_dir = ($self->{config}->{tpl_dir} || 'tpl') . '/styles/';

  # gather all styles
  opendir DIR, $style_dir or return;
  my @dir = readdir DIR;
  closedir DIR or return;

  my (@styles, @layouts);
  foreach my $d (@dir)
    {
    if (-d "$style_dir/$d")
      {
      push @styles,$d if $d =~ /^[a-zA-Z0-9-]+$/;	# valid style name
      }
    elsif (-f "$style_dir/$d")
      {
      push @layouts,$d if $d =~ /^[a-zA-Z0-9-]+\.inc$/;	# valid layout name
      }
    }
  # also add the default style
  push @styles, 'Default';

  my $curr_style = $self->{style} || '';
  my $curr_layout = $self->{layout} || '';
  $curr_layout = ',' . $curr_layout if $curr_layout;	# => ',clean' or ''

  my $list = ""; my ($line,$i);
  foreach my $style (sort @styles)
    {
    $line = $tpl;
    $line =~ s/##stylevalue##/$style$curr_layout/g;
    $line =~ s/##stylename##/$style/g;
    $list .= $line;
    }

  my $layout_list = "";
  foreach my $layout (sort @layouts)
    {
    $line = $tpl;
    $layout =~ s/\.inc//;				# clean.css => clean
    $line =~ s/##stylevalue##/$curr_style,$layout/g;
    $layout = ucfirst($layout);
    $line =~ s/##stylename##/$layout/g;
    $layout_list .= $line;
    }

  $$txt =~ s/##table##/$list/;
  $$txt =~ s/##table2##/$layout_list/;
  $txt;
  }

sub status_config
  {
  # create a configuration settings table
  my $self = shift;
  my $req = shift;

  my ($txt,$tpl) = ($self->{tpl},$self->{tplrow});

  my $cfg = $self->{config};
  my $list = ""; my ($line,$i);
  foreach my $key (sort keys %$cfg)
    {
    next if $key =~ /^_/;                               # skip internals
    $line = $tpl;
    $line =~ s/##key##/$key/eg;
    # handle array ref's, too
    if (ref($cfg->{$key}) eq 'ARRAY')
      {
      $line =~ s/##value##/ join ('<br>',@{$cfg->{$key}})/eg;
      }
    else
      {
      $line =~ s/##value##/$cfg->{$key}/g;
      }
    my $type = $cfg->type($key) || 'unknown';
    $line =~ s/##type##/$type/;
    $list .= $line;
    }
  $$txt =~ s/##table##/$list/;
  $txt;
  }

sub status_file
  {
  my ($self,$req) = @_;

  $self->status_dir($req);
  }

sub status_dir
  {
  # given a request like "cmd_status;type_(file|dir);path_PATH" will create a table of
  # a directory of PATH
  # 'browse' is the basis dir, we never leave this upwards
  # 'path' is the path appended to 'browse/' (e.g. we only go down)
  my ($self,$req) = @_;

  my $curdir = File::Spec->curdir();
  my $updir = File::Spec->updir();

  my $path = $req->{path};
  $path = $path->[0] if ref($path) eq 'ARRAY';
  $path ||= $curdir;
  $path = decode($path);			# decode for double encoded paths

  my $browse = $req->{browse} || $self->{config}->{browse_dir} || '.';
  $browse = decode($browse);			# decode for double encoded browse dir


  # if $path matches ^./$browse/ then remove this so that we land again
  # at the path (example: browse = 'target', path = './target/test' - convert
  # path to 'test'. When clicking "browse" the path will be "./$path" and thus
  # in the form below:
  $path =~ s/^\.\/$browse\///;

  for my $p ($path,$browse)
    {
    $p =~ s/\.\.//g;				# no updirs!
    crumble("$p is an absolute directory") and return undef
      if File::Spec->file_name_is_absolute($p);
    }
 
  # invalid/non-existing browse dir?
  $browse = 'target' unless -d $browse;

  my $cwd = File::Spec->catdir( $browse, File::Spec->splitdir($path));

  # invalid/non-existing browse/path?
  if (!-d $cwd)
    {
    $path = $curdir;
    $cwd = File::Spec->catdir( $browse, $path);
    }

  ${$self->{tpl}} =~ s/##cwd##/$cwd/;
  my $params_encoded = encode($req->{params} || ''); 
  my $style = $req->{style} || ''; 

  # form is double-encoded so decode it
  my $f = decode(decode($req->{form} || ''));

  ${$self->{tpl}} =~ s/##returnlink##/$f;params_$req->{params};style_$style=>/g;

  my $r = $req->copy(); $r->{params} = decode($r->{params}); $r = $r->as_request_string();
  $r =~ s/^req\d+=//;          # req0001=data => data

  ${$self->{tpl}} =~ s/##refreshlink##/$r/g;

  my $entries = Dicop::Base::read_dir ($cwd);

  crumble("Cannot read dir $path") and return undef
   if !defined $entries || ref($entries) ne 'ARRAY';			# cannot read dir?
 
  # read the template for the actual listing 
  my ($txt,$tpl) = $self->read_table_template ('dir.txt');

  my (@dirs, @files);
  my $need_size = 0; $need_size = 1 if $tpl =~ /##entrysize##/;

  # sort list into directories and files
  my $e;
  foreach my $entry (sort @$entries)
    {
    next if $entry eq $updir || $entry eq $curdir;		# skip '.' and '..'

    # XXX TODO: make this an option
    #next if $entry =~ /^\./;					# no .somedir

    $e = File::Spec->catfile( $cwd, $entry);
    my $show = $entry;
    $show = File::Spec->catfile( $path, $entry) if $path ne $curdir;
    my $size = 0;
    if ($need_size)
      {
      $size = scalar reverse (-s $e); 
      $size =~ s/(\d\d\d)(\d{1,3})/$1 $2/g;
      $size =~ s/(\d\d\d)(\d{1,3})/$1 $2/g;	# do it twice (1234 567 => 1 234 567)
      $size = scalar reverse ($size);
      }
    if (-d $e)
      {
      push @dirs, [ $show, $size ];
      }
    else
      {
      push @files, [ $show, $size ];
      }
    }
 
  # now include a dir listing 

  my $list = ''; my $rowtpl = "";

  # from foo/bar/batz make foor/bar
  my @cur_dirs = File::Spec->splitdir( $path );
  pop @cur_dirs;					# remove last dir
  $updir = File::Spec->catdir( @cur_dirs ) || '';

  $updir = $curdir if $updir eq '';

  # params are the other parameters (e.g. the fields the user already filled
  # in before pressing 'browse', so that they are preserver)
  # forms is the form we need to return to (e.g. cmd_form;type_foo;id_1) so
  # that we find our way back
  # targetfield is the name of the field user wants to select the file/dir for
  my $entryparams = { 
    params => decode($req->{params} || ''),
    form => $req->{form} || '',
    form_encoded => encode($req->{form} || ''),
    targetfield => $req->{targetfield} || '',
    params_encoded => encode($req->{params} || ''), 
    style => $req->{style} || $self->{style},
    };

  # first do 'updir'
  my $odd = 1;
  if ($path ne $curdir)
    {
    $list = $tpl;
    $self->_replace_entry_templates (\$list, $req,'One directory up',$updir,'..&nbsp;&nbsp;&nbsp;', $entryparams, 'UPDIR','', 1 , $odd, 0);
    $odd = 1 - $odd;
    }
  foreach my $f (@dirs)
    {
    $rowtpl = $tpl;
    my $sel = 0; $sel = 1 if $req->{type} eq 'dir';
    $self->_replace_entry_templates (\$rowtpl, $req,$f->[0],$f->[0],'Dir', $entryparams, 'DIR','', 1, $odd, $sel);
    $list .= $rowtpl;
    $odd = 1 - $odd;
    }
  foreach my $f (@files)
    {
    $rowtpl = $tpl;
    my $sel = 0; $sel = 1 if $req->{type} eq 'file';
    $self->_replace_entry_templates (\$rowtpl, $req,$f->[0],$f->[0],'File', $entryparams, 'FILE',$f->[1],0,$odd, $sel);
    $list .= $rowtpl;
    $odd = 1 - $odd;
    }
  $$txt =~ s/##table##/$list/;
 
  ${$self->{tpl}} =~ s/##dirlist##/$$txt/;

  $self->{tpl};
  }

sub _replace_entry_templates
  {
  # replace the templates in one dir entry (a dir or file) with the appropriate params
  my ($self,$tpl,$req,$name,$path,$type,$eparams,$class,$size,$do_link,$odd,$selectable) = @_;

  my $rt = $req->{type} || 'dir';
  my $browse = $req->{browse} || '.';
  # double encode to allow '_' in path and file names
  my $b = encode(encode($browse));
  my $p = encode(encode($path));
  
  my $form_encoded = $eparams->{form_encoded};
  my $form = $eparams->{form};
  my $params = $eparams->{params};
  my $params_encoded = $eparams->{params_encoded};
  my $targetfield = $eparams->{targetfield};
  my $style = $eparams->{style};

  # a link to follow (dir down/upwards)
  my $short_name = $name; $short_name =~ s/.*\///;
  if ($do_link)
    {
    $$tpl =~ s/##entrylink##/<a href="##selfstatus_$rt##;browse_$b;path_$p;params_$params_encoded;form_$form_encoded;targetfield_$targetfield" title="Go to $browse\/$path">$short_name&nbsp;&nbsp;<\/a>/g;
    }
  else
    {
    $$tpl =~ s/##entrylink##/$short_name/g;
    }

  # a link to select this dir/file entry
  if ($selectable)
    {
    $$tpl =~ s/##select##/<a href="##self##?req0001=$form;targetname_$targetfield;targetvalue_$b\/$p;params_$params_encoded;style_$style" title="Select this $type">Select&nbsp;<\/a>/g;
    }
  else
    {
    $$tpl =~ s/##select##/$type/g;
    }

  $odd = $odd ? '_ODD' : '';
  $$tpl =~ s/##odd##/$odd/g;
  $$tpl =~ s/##entrysize##/$size/g;
  $$tpl =~ s/##entryclass##/$class/g;

  $$tpl
  }

sub _option_list
  {
  # inside a template insert a list of things (f.i. for a SELECT field
  # to display a list of all objects, like all charsets). The list is then
  # selectable with the browser as a drop-down box
  my ($self,$txt) = @_;

  # replace texts like:
  # <SELECT NAME="charset">
  # <OPTION NAME="charset" VALUE="charsetid">##charsetdescription##
  # by the following:
  # <SELECT NAME="charset">
  # <OPTION VALUE="1">A-Z
  # <OPTION VALUE="2">A-Z,0-9

  # it also works for things like this (usefull if you have more than one
  # since the "name" charset is triggered by what is tacked at the SELECT)
  # <SELECT NAME="charset">
  # <OPTION NAME="foo" VALUE="charsetid">##charsetdescription##
  # by the following:
  # <SELECT NAME="foo">
  # <OPTION VALUE="1">A-Z
  # <OPTION VALUE="2">A-Z,0-9
  
  # additionally:
  # <SELECT NAME="charset" type=FOO,BAR>
  # where type has to match FOO or BAR otherwise the item is not included (filter on type)

  my ($tpl,$name,$type,$line,$pre,$list,$filter);
  while 
   ($$txt =~ s/(<SELECT NAME=")([a-z0-9-]+?)"(\s*\w*=?[\w,]*)>\s*\n\s*(<OPTION )name="([^"]+)" (.*)/($name,$pre,$filter,$tpl)=($2,"$1$5\">\n",($3 || ''),$4.$6);"##_o_list##"/ei)
    {
    my $n = $name; $n =~ s/^[a-z-]+?-([a-z]+)$/$1/;
    $type = $self->name_from_type($n);

    $list = $pre;
    my $filtertype = '';
    if ($filter =~ /(\w+)=([\w,]+)/)
      {
      $filtertype = $1 || ''; $filter = $2 || '';
      $filter = [ split /,/, $filter ];			# allow lists of filter words
      }
    my $items = $self->{$type};
    if (defined $items)					# charset, groups etc, but not 'foo'
      {
      foreach my $item (sort { $a <=> $b} keys %$items)
        {
        # skip items that don't fit the filter
        if ($filtertype ne '')
	  {
          my $match = 0;
          my $m = $items->{$item}->{$filtertype};
          foreach my $f (@$filter)
	    {
            $match = 1, last if ($m eq $f);
            }
          next if $match == 0;
          }
        $line = $tpl;
        $line =~ s/##$n(.*?)##/$items->{$item}->{$1}/g;
        $line =~ s/##.*?##//g; # in case of spelling errors: avoid inf. loop
        $list .= "$line\n";
        }
      }
    else
      {
      crumble ("Illegal template name '$type'\n");		# happens in testsuite
      }
    chomp($list);
    $$txt =~ s/##_o_list##/$list/;
    }
  $txt;
  }

1; 

__END__

#############################################################################

=pod

=head1 NAME

Dicop::Handler - generic request handler, base class for main server objects

=head1 SYNOPSIS

	package Dicop::MyServer;

	use base Dicop::Handler;

	# override methods:
	...

	package main;

	use Dicop::MyServer;
	$data = Dicop::MyServer->new();

	# further usage as:
	$data->handle_request();

See C<dicopd> and C<dicopp> on how to use this.

=head1 REQUIRES

perl5.008, Dicop::Item, Dicop::Request, Dicop::Config, 
Dicop::Security, Mail::Sendmail, Dicop::Event, Time::HiRes, File::Spec

=head1 EXPORTS

Exports nothing.

=head1 DESCRIPTION

Dicop::Handler is a base object for server singletons.

Upon creating such an object, the server locks a file and reads its data
into memory. Upon destroying the object, the lock is released and possible
changes are written back to the disk. From time to time the modified data
is written back to the disk, and pending emails are flushed out of the
email queue.

For each client-connect an extra file is locked to prevent from multiply
client-connects to interfere with each other. This lock is released after
the response was sent to the client.

All the data is read immidiately, but only written back if changed or a
certain time period has passed.

=head1 METHODS

=head2 authenticate_user()

	my $rc = $self->authenticate_user($username,$password);

Finds a user by his name, and then check that the hash from the given
password matches the stored hash value. Return 0 for okay, -1 for no such
user and -2 for wrong pwd.

=head2 request_auth()

A client (or proxy) connected, so check the authentication request and all the
info requests (in case of proxy). This routine also builds an initial response,
either saying helo or denying access.

This returns a list, consisting of the client, the response text and a ref to
an hash containing as keys the request IDs in case the requests came over a
proxy.

        ($client,$res,$req_map) = $self->request_auth($request);

If the returned C<$client> is undefined, than the authentication failed
entirely and C<$res> contains the error text. If the returned C<$client> is
defined and a proxy (check C<$client->type()>), C<$req_map> contains a hash
ref where the keys are the request IDs, and the values are (currently) refs
to a client object or undef. So you can check each single request and whether
it authenticated ok, or not.

=head2 name_from_type()

	$name = $self->name_from_type('foo');

Given a type as 'proxy', wil return 'proxies'. This is used to turn the
type name ('case', 'job' etc) into the field name used to store these
objects ('cases', 'jobs' etc).

=head2 class_from_type()

	$self->class_from_type('foo');

Return a class name of the form C<BASE::Foo> from the type param
from a request. The BASE part is the class of C<$self>, e.g. for
a Dicop::Handler object that would be 'Dicop::Handler::Foo', for a
Dicop::Data object it would be 'Dicop::Data::Foo' and so on.

=head2 cfg_default()
  
Given a set of keys and their values (a list or hash reference),
sets these values as default in the internal cfg object, unless
the key is already defined there.

=head2 check()

Applies self-check and crumbles if errors in data structure are present.

=head2 check_peer()

	$rc = $self->check_peer($peer,$ip,$mask,$client) = @_;

Cchecks the client IP/MASK against the peeraddress. Returns undef for ok,
otherwise an error message.

=head2 parse_requests()

This parses the form parameters as send by the client (via GET/PUT) and breaks
them into requests. It then sorts the requests into groups and returns
references to these groups (as arrays):

	($auth,$info,$reports,$requests,$forms) = $self->parse_requests();

=head2 handle_requests()

Takes the returned request groups from L<parse_requests> and handles them after
some basic checks, like for maximum number of requests, existing
authentication etc.

This also prints the result back to the client on STDOUT.
  
=head2 convert_browser_request()

Converts a hash with the submitted fields from a browser to a hash containing
(faked normal requests. Removes the unneccessary 'submit' field, and
creates an authentication request from the two fields 'auth-user' and
'auth-pass'.

=head2 log_msg()

Return a message string by number, along with embedded parameters. Works just
like Event::msg, but it also logs the message to a logfile, depending on
C<log_level> and the message code.

Typical usage:

  	$self->log_msg(430,$type,$id);
  
=head2 _clear_email_queue()

	$self->_clear_email_queue();

Delete everything in the email send queue. Mainly used by the testsuite.

=head2 flush_email_queue()
  
Tries to send all mails in the queue, and return the number of mails
successfully sent. This is called outside the code that handles a client
request, so that the client does not need to wait until all the emails are
sent.

This routine will also put all to-be-sent emails into a logfile.

=head2 type()

	$data->type();

Return the type of the server as string, e.g. either 'server' or 'proxy'.

=head2 html_header()

Read in the HTML header template and return it.

=head2 html_footer()

Read in the HTML footer template and return it.

=head2 read_template()

Read a 'normal' template file from the template dir, honouring styles (e.g.
the latter override the general templates). Inside the template text, includes
file via C<##include_filename.inc##>.

Returns the 'finished' template, ready to be filled with data as a scalar ref.
On errors, returns undef.

=head2 _read_template()

Used by L<read_template()> to just read one template file.

=head2 read_table_template()

Works just like L<read_template()>, except that it looks for an embedded table
template via C<< <!-- start --> >> and C<< <!-- end --> >> and generates
both the normal template text and a template for one row of the embedded table.

This also honours styles and includes files vi C<##include_filename.inc##>.

=head2 _include_template()

Find C<##include_filename.inc##> inside a template and include the file there.

=head2 check_auth_request()

Check the auth or info request a client/proxy sent us for basic validity.

=head2 status()

A generic routine to generate as HTML output a table listing certain objects.
When no status_xxx() routine is found by C<handle_requests()>, this one is
used as a fallback.

=head2 status_style()

Create a HTML page with a table of all available styles and layouts.

=head2 status_dir()

Creates an HTML table with files and directories, that can be used to traverse
directory trees by the user. The directories are selectable by default. See
also L<status_file()>.

=head2 status_file()

Creates an HTML table with files and directories, that can be used to traverse
directory trees by the user. The files are selectable. See
also L<status_dir()>.

=head2 get_id_list

	my @list = $data->get_id_list('job');

Return a list of all existing IDs from a given object type.

=head2 _gen_table()

An even more generic routine to generate as HTML output a table listing
certain objects. Used internally by L<search()> and L<status()>.

Examples:

    $self->_gen_table( $self->{tpl}, $self->{tplrow}, $highlight_this_id,
      [ 'cases' ], $self->_status_sort($req));

    $result_ids = { 1; }
    $job_ids = { 2 => $self->{jobs}->{2}, 3 => $self->{jobs}->{3}; }
    $self->_gen_table( $tpl, $tplrow, 0,	# 0 for none 
      [ { ids => $result_ids, type => 'results' }, { ids => $job_ids, type ='jobs') ],
      sub { $Dicop::Handler::b <=> $Dicop::Handler::a } );

=head2 get_object()

	$self->get_object($request);


Generalized form to return object from { id => X, type => FOO }. You need to
overwrite this routine in your code to actually return the object (depending
on how you store them). For instance, this is used in edit/add forms.

=head2 _check_templates()

	$self->_check_templates ( 'mail', 'no_warn', qw/new_job failed .../);

Checks that the given list of template files does exist. C<$type> can be 'mail',
'event' etc. If true, the second parameter inhibits warning messages (used by
the testsuite).

=head2 _construct_file_names

	$self->_construct_file_names( $args, $cfg, @OBJECTS);

Construct C<< $self->{filenames} >> for flush() from the given object list.
Does also set C<< $self->{dir} >>.

=head1 BUGS

See the L<BUGS> file for details.

=head1 AUTHOR

(c) Bundesamt fuer Sicherheit in der Informationstechnik 1998-2006

DiCoP is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License version 2 as published by the Free
Software Foundation.

See L<http://www.bsi.de/> for more information.

=cut
