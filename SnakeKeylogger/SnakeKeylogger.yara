/*
	SnakeKeylogger Yara Rule
	Author: Martin Georgiev
	Date: 25/3/23
*/

rule Jigsaw_Ransomware {
	meta:
		description = "Yara rule for detecting SnakeKeylogger spyware"
		author = "Martin Georgiev"
		university = "Abertay University"
		degree = "BSc Hons Ethical Hacking"
		date = "25/3/23"
		md5 = "6f0d31986bdac094d0903a1a44cc5432"
		sha256 = "7e1d956fe3ab418c915d24faecac0798be86b86a4244580ebf8af91bc01f752f"
		note = "This yara rule works only for the specified sample. The sample did not contain any obvious strings which can be found in other SnakeKeylogger variants."
		
	strings:
		// Generic Nullsoft strings
		$p1 = "Nullsoft" fullword wide ascii
		$p2 = "\\Microsoft\\Internet Explorer\\Quick Launch" fullword wide ascii // IE related registry
		$p3 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide ascii // CurrentVersion registry
		// Clipboard functions
		$s1 = "CloseClipboard" ascii
		$s2 = "SetClipboardData" ascii
		$s3 = "EmptyClipboard" ascii
		$s4 = "OpenClipboard" ascii
		// Retrieve messages from windows on the current thread and dispatch them.
		$s5 = "PeekMessageW" ascii
		$s6 = "DispatchMessageW" ascii
		
		
	condition:
	uint16(0) == 0x5a4d and filesize < 1000KB and any of ($p*) and all of ($s*) // Check first byte (DOS executable), if under 1000KB and has any of $p and any of $s 
	}
	