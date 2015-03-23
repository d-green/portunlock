#!/usr/bin/perl
use CGI qw(:standard);
use CGI::Carp qw(warningsToBrowser fatalsToBrowser);
use Net::OpenSSH;
use Net::Telnet;
use CGI::Session '-ip_match';
use CGI::Cookie;
use Authen::Simple::ActiveDirectory;
use Switch;

open CONFIG, "/usr/local/etc/port.conf" or die "Couldn't open file: $!";
while (<CONFIG>) {
    chomp;
    if (!($_ =~ /^\#/)) {
        my ($key, $value) = split(/=/, $_);
        if($key eq 'credentials'){ $credentials=$value; }
        if($key eq 'domain'){ $domain=$value; }
        if($key eq 'domain_controller'){ $domain_controller=$value; }
        if($key eq 'loghost'){ $loghost=$value; }
        if($key eq 'facility'){ $facility=$value; }
        if($key eq 'severity'){ $severity=$value; }
        if($key eq 'logprefix'){ $logprefix=$value; }
        if($key eq 'sshport'){ $sshport=$value; }
        if($key eq 'switches_in_row'){ $switches_in_row=$value; }
        if($key eq 'host'){
    	    my($val,$disp)=split(/:/,$value);
    	    push @hosts,[$val,$disp];
    	}
        if($key eq 'user'){
    	    my($val,$disp)=split(/:/,$value);
    	    push @users,[$val,$disp];
    	}
    }
}
close CONFIG;
my $promptEnd = '/\w+[\$\%\#\>]\s{0,1}$/o';

# $Net::OpenSSH::debug=-1;
sub ltrim { my $s = shift; $s =~ s/^\s+//;       return $s };
sub rtrim { my $s = shift; $s =~ s/\s+$//;       return $s };
sub  trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s };
sub tell_bigbro { my $logmsg = shift; open(my $fh, "| logger -p $facility.$severity -d -n $loghost"); print $fh $logprefix.$logmsg . "\n"; close($fh);}
sub validate_host { my $ipadr = shift;
   if($ipadr=~/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ &&(($1<=255  && $2<=255 && $3<=255  &&$4<=255 )))
   {return 'ip-ok';} else{return 0;}
}
sub validate_port { my $swport = shift;
   if($swport=~/^(\w{2})(\d{1})\/(\d{1,2})$/ && $2<=47 )
   {return 'port-ok';} else{return 0;}
}

my $q = new CGI;
$q->charset('UTF-8');

my $session = new CGI::Session("driver:File", $q, {Directory=>"/tmp"});
my $cookie = $q->cookie( "CGISESSID", $session->id );
$session->expire(180);

print header(-charset=>'utf-8',-cookie=>$cookie);
print start_html("Interface Status");
print '<link href="/cisco/style.css" rel="stylesheet" type="text/css">';
$authentificated = $session->param('authentificated');
$username        = $session->param('username');
$friendlyname    = $session->param('friendlyname');

if  ( 'POST' eq $q->request_method && $q->param('username') && $q->param('password') )
{
    my $ad = Authen::Simple::ActiveDirectory->new( host  => $domain_controller, principal => $domain  );
    $username=$q->param('username');
    $password=$q->param('password');
    foreach $thisuser (@users) {
      if( ($thisuser->[0]) eq $username ){
        $friendlyname = $thisuser->[1];
      }
    }
    if($ad->authenticate( $username, $password ) && $friendlyname )
    {
	$session->param("username", $username);
	$session->param("friendlyname",$friendlyname);
	$session->param("authentificated",'yes');
	$authentificated='yes';
    }
    else
    {
	print 'Bad username or password. Also, you have to be a SuperHero to use it. Aren\'t you?';
	print end_html;
	$session->flush();
	exit(0);
    }
}
if  ( 'POST' eq $q->request_method && ($q->param('submit') eq 'Logout' ))
{
	print 'Logged out.';
	print end_html;
	$session->delete();
	$session->flush();
	exit(0);
}
if ( $authentificated ne 'yes' ) {
    print start_form(-name => '', -method  => 'POST', -enctype => &CGI::URL_ENCODED, -action => 'port.pl');
    print textfield(-name=>'username', -default=>'', -override=>1, -size=>10, -maxlength=>30);
    print "&nbsp";    
    print password_field(-name=>'password',-value=>'',-size=>10, -maxlength=>30);
    print "&nbsp";    
    print submit(-name=>'submit', -value=>'Login');
    print end_form;
    print end_html;
}
if ( $authentificated eq 'yes' ) {
    print start_form(-name => '', -method  => 'POST', -enctype => &CGI::URL_ENCODED, -action => 'port.pl');
    print '<br/>Logged as: &nbsp',$friendlyname,'&nbsp';
    print submit(-name=>'submit', -value=>'Logout');
    print end_form;
}
###############################################
# Web form to ask port description
#
###############################################
if ('GET' eq $q->request_method && $q->param('host') && $q->param('act') eq 'askdesc' && ( $authentificated eq 'yes' ) ) 
{
    my $host = $q->param('host');
    my $port = $q->param('port');
    my $desc = $q->param('desc');
    if(!validate_port($port) || !validate_host($host) ){
	print 'Bad parameters.';
	print end_html;
	$session->flush();
	exit(0);
    }
    print start_form(-name => 'сhange_desc', -method  => 'GET', -enctype => &CGI::URL_ENCODED, 
                 -action => 'port.pl');
    print 'Enter description for '.$port. ' on '.$host.':';
    print textfield(-name=>'desc', -default=>$desc, -override=>1, -size=>10, -maxlength=>30);
    print $q->hidden(-name => 'host',-value => $host);
    print $q->hidden(-name => 'port',-value => $port);
    print  '<input type="hidden" name="act" value="changedesc" />';
    print submit(-name=>'submit', -value=>'Set');
    print end_form;
}
###############################################
# List switches
# 
###############################################
if( $authentificated eq 'yes' ){
    print '<table class="switches">';
    $i=0;
    print '<tr>';
    foreach $thishost (@hosts) {
        if($i>$switches_in_row){    print '</tr><tr>'; $i=0;}
        if( ($thishost->[0]) eq ($q->param('host'))  ){
	    print '<td class="swsel"><a href=?host='.$thishost->[0].'>'.$thishost->[1].'</a></td>';
        }
        else{
	    print '<td class="swunsel"><a href=?host='.$thishost->[0].'>'.$thishost->[1].'</a></td>'; 
        }
	$i++;
    }
    print '</tr>';
    print '</table>';
}
###############################################
# Enable shutdowned port
#
###############################################
if ('GET' eq $q->request_method && $q->param('host') && $q->param('act') eq 'enable' && ( $authentificated eq 'yes' )) 
{
    my $act = $q->param('act');
    my $host = $q->param('host');
    my $port = $q->param('port');
    if(!validate_port($port) || !validate_host($host) ){
	print 'Bad parameters.';
	print end_html;
	$session->flush();
	exit(0);
    }
    print 'Have to '.$act.' port '.$port.' on '.$host.' <br/><a href=?act=list&host='.$host.'>Go Back</a>';
    tell_bigbro('User '.$username.' '.$act.' '.$port.' on '.$host);        
    my $ssh = Net::OpenSSH->new($credentials.'@'.$host.':'.$sshport, 
			    master_opts => [-o => "StrictHostKeyChecking=no"]);
    $ssh->error and
       die "Couldn't establish SSH connection: ". $ssh->error;
    $command="conf term\ninterface ".$port."\nno shutdown\nexit\nexit\nwrite memory\nexit";
    my $output = $ssh->capture({stdin_data =>$command  });
}
###############################################
# Disable port (port must be "notconnect")
#
###############################################
if ('GET' eq $q->request_method && $q->param('host') && $q->param('act') eq 'disable' && ( $authentificated eq 'yes' ) ) 
{
    my $act = $q->param('act');
    my $host = $q->param('host');
    my $port = $q->param('port');
    if(!validate_port($port) || !validate_host($host) ){
	print 'Bad parameters.';
	print end_html;
	$session->flush();
	exit(0);
    }
    print 'Have to '.$act.' port '.$port.' on '.$host.' <br/><a href=?act=list&host='.$host.'>Go Back</a>';
    tell_bigbro('User '.$username.' '.$act.' '.$port.' on '.$host);    
    my $ssh = Net::OpenSSH->new($credentials.'@'.$host.':'.$sshport, 
			    master_opts => [-o => "StrictHostKeyChecking=no"]);
    $ssh->error and
       die "Couldn't establish SSH connection: ". $ssh->error;
    $command="conf term\ninterface ".$port."\nshut\nexit\nexit\nwrite memory\nexit";
    my $output = $ssh->capture({stdin_data =>$command  });
}
###############################################
# Unlock port locked by port security
#
###############################################
if ('GET' eq $q->request_method && $q->param('host') && $q->param('act') eq 'unlock' && ( $authentificated eq 'yes' )) 
{
    my $act = $q->param('act');
    my $host = $q->param('host');
    my $port = $q->param('port');
    if(!validate_port($port) || !validate_host($host) ){
	print 'Bad parameters.';
	print end_html;
	$session->flush();
	exit(0);
    }
    print 'Have to '.$act.' port '.$port.' on '.$host.' <br/><a href=?act=list&host='.$host.'>Go Back</a>';
    tell_bigbro('User '.$username.' '.$act.' '.$port.' on '.$host);        
    my $ssh = Net::OpenSSH->new($credentials.'@'.$host.':'.$sshport, 
			    master_opts => [-o => "StrictHostKeyChecking=no"]);
    $ssh->error and
       die "Couldn't establish SSH connection: ". $ssh->error;
    $command="clear port sti int ".$port."\nconf term\ninterface ".$port."\nshut\nno shut\nexit\nexit\nwrite memory\nexit";
    my $output = $ssh->capture({stdin_data =>$command  });
}
###############################################
# Change description of the port
#
###############################################
if ('GET' eq $q->request_method && $q->param('host') && $q->param('act') eq 'changedesc' && ( $authentificated eq 'yes' ))
{
    my $act = $q->param('act');
    my $host = $q->param('host');
    my $port = $q->param('port');
    my $desc = $q->param('desc');
    if(!validate_port($port) || !validate_host($host) ){
	print 'Bad parameters.';
	print end_html;
	$session->flush();
	exit(0);
    }
    print 'Have to '.$act.' port '.$port.' on '.$host.' <br/><a href=?act=list&host='.$host.'>Go Back</a>';
    tell_bigbro('User '.$username.' '.$act.' '.$port.' on '.$host.' to '.$desc);        
    my $ssh = Net::OpenSSH->new($credentials.'@'.$host.':'.$sshport,
			    master_opts => [-o => "StrictHostKeyChecking=no"]);
    $ssh->error and
       die "Couldn't establish SSH connection: ". $ssh->error;
    $command="configure terminal\ninterface ".$port."\ndescription $desc\nexit\nexit\nwrite memory\nexit";
    my $output = $ssh->capture({stdin_data =>$command  });
}
#################################################
# Main switchports table for host
#
#################################################
if ('GET' eq $q->request_method && $q->param('host') && ( $authentificated eq 'yes' )) 
{
    my $host = $q->param('host');
    if( !validate_host($host) ){
	print 'Bad parameters.';
	print end_html;
	$session->flush();
	exit(0);
    }
    my $ssh = Net::OpenSSH->new($credentials.'@'.$host.':'.$sshport, 
			    master_opts => [-o => "StrictHostKeyChecking=no"]);
    $ssh->error and
       die "Couldn't establish SSH connection: ". $ssh->error;
    $output=$ssh->capture("show interface status");
    @output=split('\n',$output);
    splice(@output,0,3); #remove header
    my $pPort={},$pName={},$pStatus={},$pVlan={},$pDuplex={},$pSpeed={},$pType={};
    foreach my $val (@output) {
       $port=$host.'-'.trim(substr($val,0,9));  
       $pPort{$port}.=trim(substr($val,0,9));
       $pName{$port}.=trim(substr($val,10,18));
       $pStatus{$port}.=trim(substr($val,29,12));
       $pVlan{$port}.=trim(substr($val,42,10));
       $pDuplex{$port}.=trim(substr($val,53,7));
       $pSpeed{$port}.=trim(substr($val,61,5));   
       $pType{$port}.=trim(substr($val,67,20));      
    }
    my $ssh = Net::OpenSSH->new($credentials.'@'.$host.':'.$sshport, 
			    master_opts => [-o => "StrictHostKeyChecking=no"]);
    $ssh->error and
       die "Couldn't establish SSH connection: ". $ssh->error;
    $output=$ssh->capture("show mac address-table");
    @output=split('\n',$output);
    splice(@output,0,5);  #remove header
    splice(@output,-1,1); # remove footer
    my $pMac={};
    foreach my $val (@output){
       $port=$host.'-'.trim(substr($val,38,6));  
       $pMac{$port}.=' '.trim(substr($val,8,14));
    }
    print '<table class="ports">';
    print '<tr class="header"><td class="ports">Port</td><td class="ports">Description</td><td class="ports">Status</td>'.
          '<td class="ports">Vlan</td><td class="ports">Duplex</td><td class="ports">Speed</td>'.
          '<td class="ports">Type</td><td class="ports">Mac address table</td></tr>';
    foreach (sort {$pPort{$a} cmp $pPort{$b}} keys %pPort) {
        print '<tr';
        switch($pStatus{$_}){
	    case 'connected'  { print ' class="connected">'  }
    	    case 'notconnect' { print ' class="notconnect">' }
    	    case 'disabled'   { print ' class="disabled">' }
            else              { print ' class="errdisabled">' }
        };
#    	print '<td class="ports">',$_,'</td>';            
    	print '<td class="ports">',$pPort{$_},'</td>';
    	print '<td class="ports"><a href=?act=askdesc&host='
    	          .$host.'&port='.$pPort{$_}.'&desc='.$pName{$_}.'>',$pName{$_},'</a></td>';
    	switch($pStatus{$_}){
    	    case 'connected'    { 
	    	print '<td class="ports">',$pStatus{$_},'</td>';
		}
    	    case 'notconnect'   { 
	    	print '<td class="ports"><a href=?act=disable&host='.$host.'&port='.$pPort{$_}.'>',$pStatus{$_},'</a></td>';        	
        	}
    	    case 'disabled'     { 
		print '<td class="ports"><a href=?act=enable&host='.$host.'&port='.$pPort{$_}.'>',$pStatus{$_},'</a></td>';        	
    	    }
            case 'err-disabled' { 
	        print '<td class="ports"><a href=?act=unlock&host='.$host.'&port='.$pPort{$_}.'>',$pStatus{$_},'</a></td>';        	
            }
        };
    	print '<td class="ports">',$pVlan{$_},'</td>';   
    	print '<td class="ports">',$pDuplex{$_},'</td>';
    	print '<td class="ports">',$pSpeed{$_},'</td>';   
    	print '<td class="ports">',$pType{$_},'</td>';      
    	print '<td class="macaddress">',$pMac{$_},'</td>';      
    	print '</tr>';   
    }
    print '</table>';     
}
print end_html;
