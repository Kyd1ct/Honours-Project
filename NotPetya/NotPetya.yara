/*
	NotPetya Yara Rule
	Author: Martin Georgiev
	Date: 27/11/22
	Reference: Georgiev, M. (2022). Analysis and Comparison of WannaCry and NotPetya. [online] Github.
			   Available at: https://github.com/Kyd1ct/Analysis_and_Comparison_of_WannaCry_and_NotPetya/commit/8ff0172ef1877dc6035d554379cdae4d40e8dbf4
			   [Accessed 29 Nov. 2022].
*/

rule NotPetya_Wiper {
	meta:
		description = "Yara rule for detecting NotPetya wiper sample from 2017"
		author = "Martin Georgiev"
		university = "Abertay University"
		degree = "BSc Hons Ethical Hacking"
		date = "27/11/22"
		md5 = "db349b97c37d22f5ea1d1841e3c89eb4"
		sha256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
		
	strings:
		// Generic Ransomware messages
		$p1 = "Ooops, your important files are encrypted." fullword wide ascii
		$p2 = "Send your Bitcoin wallet ID and personal installation key to e-mail " fullword wide
		// NotPetya related commands
		$s1 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1 " fullword wide // creates a process call to execute itself with rundll32.exe
		$s2 = "-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 " fullword wide // runs itself with rundll32.exe on newly infected machines
		$s3 = "fsutil usn deletejournal /D %c:" fullword wide // deletes USN journal (changes on drive C)
		$s4 = "wevtutil cl Setup & wevtutil cl System" fullword wide ascii //clears Setup and System logs
		$s5 = "dllhost.dat" fullword wide //psexec.exe execution for local network propagation
		$s6 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" " fullword wide //remote execution with wmic.exe
		$s7 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d" fullword wide //schedule system reboot at noon
		$s8 = "u%s \\\\%s -accepteula -s " fullword wide // automatically accepts EULA upon execution to remain hidden
		
	condition:
	uint16(0) == 0x5a4d and filesize < 1000KB and any of ($p*) and all of ($s*) // Check first byte (DOS executable), if under 1000KB and has any of $p and all of $s 
	}