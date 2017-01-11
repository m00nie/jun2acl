#!/usr/bin/perl
###########################################################
# jun2acl
# Very simple (?) script to (try) and convert juniper firewall
# 	rules into cisco extended acls
#
# Run with "perl jun2acl myfile" where myfile contains your config
#	either whole config or just firewall section in "display set" 
#	format. 
#
# Author m00nie @ https://www.m00nie.com/
# This software is provided as is an should be used at your own
#	risk entirely!
# 
# Version 1.0 - Intial release (probably missing a LOT of 
#	corner cases!)
#
# Dependencies on Fedora/Centos/Red Hat
# yum install perl-NetAddr-IP perl-Switch
##########################################################
use NetAddr::IP;
use Switch;
use warnings;
use strict;
# Set to 1 for debug (quite verbose!)
my $debug = 0;
# Here you can change what protocol we assign to source and 
# destination services/ports
# Default is both udp and tcp if not found in one of the below
my @tcp_ports = ("http","ftp","ftp-data","telnet","ssh","80","established","21","3389","rdp");
my @udp_ports = ("snmp","53","dns","ntp","123");
##########################################################
my ($fc, $tc, $sc, $fv) = ("x") x 4;
my @source_addr;
my @dest_addr;
my @dest_port;
my @protocol;
my $log = 0;
my $permit;
my @source_port;
my $tcp_estab;

if ($#ARGV != 0) {
        print "Usage: jun2acl.pl MYFILE\n\n";
        exit;
} 
my $filename = $ARGV[0];
open my $data, $filename or die "Could not open '$filename' $!\n";

while (my $line = <$data>) {
	if ($line =~ /(^set firewall filter .*$)/) {
		my @x = split (' ',$1);
		my $fw = $x[3];
		my $te = $x[5];
		my @sd = @x[7 .. $#x];
		if ($debug == 1) {
			print "DEBUG - Line is @x\n";
			print "DEBUG - fw is $fw, fc is $fc\n";
			print "DEBUG - te is $te, tc is $tc\n";
			print "DEBUG - sd is @sd\n";	
		}
		if ($fw =~ $fc) {
			if ($te =~ $tc) { 
				# Additional components for current term in current ACL
				clean(@sd);				
			} else {
				if ($debug == 1) {
					# New Term in current ACL
					print "DEBUG ---found new term called $te\n";
				}
				print_all($tc, $fw);
				empty();				
				clean(@sd);
				$tc = $te;
				$fc = $fw;
			}
		} elsif ($fw ne $fc) {
			# Seeing this ACL for the first time (must be new term too)
			if ($debug == 1) {
				print "DEBUG - Found new firewall called $fw\n";
				print "DEBUG ---found new term called $te\n";
			}
			if ($te ne "x") {
				# This is a new Firewall but not the first run
				print_all($tc, $fc);
				empty();
				clean(@sd);
				$tc = $te;
				$fc = $fw;
			} else {
				# This should be the first Firewall and term
				$tc = $te;
				$fc = $fw;
			}
		}		
	}
}
close $data; 
# Catch the last line!
print_all($tc, $fc);
##########################################################
# Print out ACLs 
sub print_all {
	my @sourcew;
	my @destw;
	my $sport;
	my $proto;
	my ($term, $fire) = @_;
	if ($term eq "x") { return }
	if (!$permit) { $permit = "permit"}
	if (!@source_addr) { push (@source_addr, "any"); }
	if (!@dest_addr) { push (@dest_addr, "any"); }
	if (!@protocol) { push (@protocol, "ip"); }
	if (!@dest_port) { push (@dest_port, " "); }
	if ($debug == 1) {
		print "DEBUG (print_all) - Sources: @source_addr\n";
		print "DEBUG (print_all) - Source ports: @source_port\n";
		print "DEBUG (print_all) - Destinations: @dest_addr\n";
		print "DEBUG (print_all) - Dest Port: @dest_port\n";
		print "DEBUG (print_all) - Protcol: @protocol\n";
		print "DEBUG (print_all) - Tcp Established: $tcp_estab\n";
		print "DEBUG (print_all) - Permit: $permit\n";
		print "DEBUG (print_all) - Log: $log\n\n\n";
	}	
	if ((($dest_port[0] ne " ") or (@source_port)) and $protocol[0] =~ "ip") {
		switch ($dest_port[0]) {
			if ($debug == 1) {
				print "DEBUG (print_all) - DEST PORT IS $dest_port[0]\n\n";
				print "DEBUG (print_all) - UDP: @udp_ports\n";
				print "DEBUG (print_all) - TCP: @tcp_ports\n";
			}
			case [@udp_ports]			{ @protocol = (); push (@protocol, "udp"); }
			case [@tcp_ports]			{ @protocol = (); push (@protocol, "tcp"); }
			else 						{ @protocol = (); push (@protocol, ("tcp", "udp")); }
		}
	} 
	foreach my $source (@source_addr) {
		if ($source ne "any") { 
			@sourcew = get_wild($source); 	
			if ($sourcew[1] eq "0.0.0.0") { $sourcew[1] = $sourcew[0]; $sourcew[0] = "host"}
		}
		else { @sourcew = $source } 
		foreach my $dest (@dest_addr) {
			if ($dest ne "any") {
                        	@destw = get_wild($dest);
                	        if ($destw[1] eq "0.0.0.0") { $destw[1] = $destw[0]; $destw[0] = "host"}
        	     	} else { @destw = $dest }
			if (@source_port) { 
				foreach my $sport (@source_port) {
					foreach $proto (@protocol) {
						foreach my $dport (@dest_port) {
                        	print "ip access-list extended $fire $permit";
                        	print " $proto @sourcew eq $sport @destw";
                        	switch ($dport) {
                            	case " "                { print ""; }
                            	case m/(\d+)\-(\d+)/    { print " range $dport"; }
                            	else                    { print " eq $dport"; }
                        	}
                        	if ($log eq "1") {
                        		print " log\n";
                        	} else {
                        		print "\n";
                        	}
						}
					}
				}
			} else {
				foreach $proto (@protocol) {
					foreach my $dport (@dest_port) { 
						print "ip access-list extended $fire $permit $proto @sourcew @destw";
						switch ($dport) {
			        		case " "           		{ print ""; }
							case m/(\d+)\-(\d+)/	{ print " range	$dport"; }	
							else 					{ print " eq $dport"; }
						}
						if ($log eq "1") {
							print " log\n";
						} else {
							print "\n";
						}
					}
				}
			}
		}
	}	
}
# Clean our variables
sub empty {
	@source_addr = ();
	@source_port = ();
	@dest_addr = ();
	@dest_port = ();
	@protocol = ();
	$log = "";
	$tcp_estab = "";
	$permit = "";	
}
# Collect components
sub clean {
	my @y = @_;	
	switch ($y[0]) {
        case "source-address"           { push (@source_addr, $y[1]); }
        case "address"                  { push (@source_addr, $y[1]); }
        case "log"                      { $log = 1; }
        case "destination-address"      { push (@dest_addr, $y[1]); }
        case "destination-port"         { push (@dest_port, $y[1]); }
		case "protocol"					{ push (@protocol, $y[1]); }
		case "accept"					{ $permit = "permit"; }
		case "reject"					{ $permit = "deny" ; }
		case "source-port"				{ push (@source_port, $y[1]); }
		case "tcp-established"			{ push (@dest_port, "established"); }
        case "port"						{ push (@dest_port, $y[1]); }
		case "count"					{ $log = 1; }
		case "syslog"					{ $log = 1; }
		else 							{ print "Couldnt parse details of @y[0 .. $#y]\n"; }
	}
}
# Check if the IPs we find are valid 
sub validate_ip {
	# There was validation I might readd in future
	my $ip_to_check = @_;
	if (is_ipv4($ip_to_check)) {
        	print "Looks like an valid ipv4 address\n";
		return 1;
	}
  	else {
        	print "Not a valid ipv4 address\n";
		return 0;
	}
}
# Generate wildcard for Cisco ACL
sub get_wild {
	my @sub_to_wild = @_;
	my @wild = NetAddr::IP->new(@sub_to_wild)->wildcard();
	return @wild;
}
