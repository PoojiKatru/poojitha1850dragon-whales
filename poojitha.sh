-----Trial 1 for Linux Bash Scripting -----
#TableofContents
#updates
#installing and enabling auditing
#enabling firewall
#make log dir
#create/clear log files
# Add additional instructions to log file
# install libpam-cracklib to set password details up - fix
# Pam config - fix 
# password aging policy - fix
# password lockout #add line of code to enable it 
# SSH daemon config

# Lists all cronjobs & output to /var/local/cronjoblist.log - fix
# List all connections, open or listening
# Install clam antivirus - fix this
# Update clam signatures - fix
# Run a full scan of the "/home" directory
#ssh
#insecure permissions on shadow file
#SSHD service installed + started

#checking for the services that are installed
#IPv6 disable - fix
# prohibited software
#install updates from imoprtant security updates - do this
#stystem automatically checks for updates daily

# upgrade all installed packages







#SERVICES - ADD DEM
#Delete John the Ripper
#shadow file - insecure permissions

#!/bin/bash
#updates
echo "getting updates"
sudo apt-get update

#installing and enabling auditing
echo "Installing auditing daemon"
sudo apt-get install auditing
echo "enabling auditing"
auditctl -e 1 > /var/local/audit.log

#enable firewall
echo "enabling UFW"
ufw enable

# make log dir
echo "creating /var/local" 
mkdir /var/local/ #already exists

# Create/clear log files
echo "creating log files in /var/local"
echo -n "" > /var/local/netstat.log
echo -n "" > /var/local/ASAO.log
echo -n "" > /var/local/mediafiles.log
echo -n "" > /var/local/cronjoblist.log

# Add additional instructions to log file
echo "adding instructions to log file"
echo "getent group <groupname> |||| Users in group" >> /var/local/ASAO.log
echo "edit /etc/audit/auditd.conf" >> /var/local/ASAO.log
echo "Don't Forget to Restart" >> /var/local/ASAO.log
echo "more password stuff @ https://www.cyberciti.biz/tips/linux-check-passwords-against-a-dictionary-attack.html" >> /var/local/ASAO.log

# install libpam-cracklib to set password details up
echo "installing libpam-cracklib for passwords"
sudo apt-get update -y
sudo apt-get install -y libpam-modules


# Pam config
echo "changing PAM config"
# grep for 'pam_unix.so' and get line number
PAMUNIX="$(grep -n 'pam_unix.so' /etc/pam.d/common-password | grep -v '^#' | cut -f1 -d:)"
sed -e "${PAMUNIX}s/.*/password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512 remember=5/" /etc/pam.d/common-password > /var/local/temp.txt
#grep for 'pam_cracklib.so' and get line number
PAMCRACKLIB="$(grep -n 'pam_cracklib.so' /etc/pam.d/common-password | grep -v '#' | cut -f1 -d:)"
sed -e "${PAMCRACKLIB}s/.*/password	requisite	pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 1credit=-2 ocredit=-1/" /var/local/temp.txt > /var/local/temp2.txt
rm /var/local/temp.txt
cp /etc/pam.d/common-password /etc/pam.d/common-password.old
mv /var/local/temp2.txt /etc/pam.d/common-password

# password aging policy
echo "setting passwords to reset after 30 days"
PASSMAX="$(grep -n 'PASS_MAX_DAYS' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
sed -e "${PASSMAX}s/.*/PASS_MAX_DAYS	90/" /etc/login.defs > /var/local/temp1.txt
PASSMIN="$(grep -n 'PASS_MIN_DAYS' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
sed -e "${PASSMIN}s/.*/PASS_MIN_DAYS	10/" /var/local/temp1.txt > /var/local/temp2.txt
PASSWARN="$(grep -n 'PASS_WARN_AGE' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
sed -e "${PASSWARN}s/.*/PASS_WARN_AGE	7/" /var/local/temp2.txt > /var/local/temp3.txt
cp /etc/login.defs /etc/login.defs.old
mv /var/local/temp3.txt /etc/login.defs
rm /var/local/temp1.txt /var/local/temp2.txt

# password lockout #add line of code to enable it 
echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth

# SSH daemon config
echo "disabling root login"
# get the line number of the PermitRootLogin line
PRL="$(grep -n 'PermitRootLogin' etc/ssh/sshd_config | grep -v '#' | cut -f1 -d:)"
sed -e "${PRL}s/.*/PermitRootLogin no/" /etc/ssh/sshd_config> /var/local/temp1.txt
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.old
mv /var/local/temp1.txt /etc/ssh/sshd_config

# Find all video files
#open up the log
#find media files in only home directories

echo "Finding Media Files"
echo "||||Video Files||||" >> /var/local/mediafiles.log
locate *.mkv *.webm *.flv *.vob *.ogv *.drc *.gifv *.mng *.avi *.mov *.qt *.wmv *.yuv *.rm *.rmvb *.asf *.amv *.mp4 *.m4v *.mp *.m?v *.svi *.3gp *.flv *.f4v >> /var/local/mediafiles.log
echo "||||Audo Files||||" >> /var/local/mediafiles.log
locate *.3ga *.aac *.aiff *.amr *.ape *.arf *.asf *.asx *.cda *.dvf *.flac *.gp4 *.gp5 *.gpx *.logic *.m4a *.m4b *.m4p *.midi *.mp3 *.pcm *.rec *.snd *.sng *.uax *.wav *.wma *.wpl *.zab >> /var/local/mediafiles.log

# Lists all cronjobs & output to /var/local/cronjoblist.log
echo "Outputting cronjobs to /var/local/cronjoblist.log"
crontab -l >> /var/local/cronjoblist.log

# List all connections, open or listening
echo "finding open connections and outputting to /var/local/netstat.log"
ss -an4 > /var/local/netstat.log

# Install clam antivirus
echo "installing clam antivirus"
sudo apt-get install clamav 
sudo freshclam


# Update clam signatures
echo "updating clam signatures"
freshclam

# Run a full scan of the "/home" directory
echo "running full scan of /home directory"
clamscan -r /home


#ssh
if [ $sshYN == no ]
then
	ufw deny ssh
	sudo apt-get purge openssh-server -y -qq
	printTime "SSH port has been denied on the firewall. Open-SSH has been removed."
elif [ $sshYN == yes ]
then
	apt-get install openssh-server -y -qq
	ufw allow ssh
	cp /etc/ssh/sshd_config ~/Desktop/backups/	
	echo Type all user account names, with a space in between
	read usersSSH
	echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 2200\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's ~/.rhosts and ~/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
	service ssh restart
	mkdir ~/.ssh
	chmod 700 ~/.ssh
	ssh-keygen -t rsa
	printTime "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
else
	echo Response not recognized.
fi
printTime "SSH is complete."

#insecure permissions on shadow file
echo what is the permission on the shadow file?
sudo ls -l /etc/shadow
read shadowfileYN
if [ $shadowfileYN == yes ]
	then 
	echo fixing the problem
	chmod 640 /etc/shadow
fi

#SSHD service installed + started
echo installing openssh-server
sudo apt-get install openssh-server
echo opening the openssh-server
sudo systemctl start sshd

#checking for the services that are installed
echo checking services that are active
systemctl list-units --type=service  --state=active

echo Disable nginx?
read nginxYN
if [ $nginxYN == yes ]
then
	sudo systemctl stop nginx
	sudo systemctl disable nginx
fi
#IPv6 disable
echo Disable IPv6?
read ipv6YN
if [ $ipv6YN == yes ]
then
	echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -p >> /dev/null
	printTime "IPv6 has been disabled."
fi

# prohibited software
echo removing wireshark
sudo apt remove wireshark
echo removing ophcrack
sudo apt remove ophcrack




# upgrade all installed packages
echo "installing updates"
echo excluding PostgreSQL 12.2  
sudo apt-mark hold PostgreSQL
apt-get upgrade -y
