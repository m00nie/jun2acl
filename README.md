# jun2acl
"translate" Juniper junos firewall config to Cisco ACLs


More info @ https://www.m00nie.com/2014/10/jun2acl-juniper-to-cisco-acl-script/

Recently we’ve needed to migrate an inherited environment  away from Juniper Junos and onto Cisco IOS. As part of this a lot (!) of old an quite nasty firewall filter config needed to be converted to Cisco ACL style. Unfortunately (maybe for a good reason???) there doesnt already seem to be any easily available tool to do this conversion and doing this by hand would have been quite a :'( job to ask anyone to do so I’ve made a quick and nasty script to try and do most of the heavy lifting for us.

It takes an input file as an argument (eg “perl jun2acl MyJunFW”) and expects this file to contain either the whole router or Firewall section in ‘set’ format (show configuration | display set)

Then it should return an extended Cisco ACL for each firewall filter name found. I’ve done a fair bit of testing but this is provided as is and you should review any config before deploying and expecting it to work 
