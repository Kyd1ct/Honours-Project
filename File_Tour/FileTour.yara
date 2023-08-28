/*
	FileTour Yara Rule
	Author: Martin Georgiev
	Date: 21/02/23
*/

rule FileTour_Bundleware {
	meta:
		description = "Yara rule for detecting FileTour malicious boundleware with SmartPDF"
		author = "Martin Georgiev"
		university = "Abertay University"
		degree = "BSc Hons Ethical Hacking"
		date = "21/02/23"
		md5 = "146d5e3ba35287954f1b61bf2ef52e24"
		sha256 = "ab5e597bf7316bd8fcaeca8cddeec38a9585704a7929d50ea92ba603b038d7f3"
		
	strings:
		// NOTE: This rule has been specifically made for hash specified above.
		// Some of the $p strings may be present in legitimate files.
		// Checking the strings of the file is advised to ensure authenticity if ran on other strains.
		$p1 = "..\\sim.exe" fullword wide ascii
		$p2 = "SMART INSTALL MAKER" ascii
		$p3 = "The setup files are corrupted. Please obtain a new copy of the program." ascii 
		$p4 = "inflate 1.1.4 Copyright 1995-2002 Mark Adler" ascii // Compression tool
		$p5 = "deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly" ascii // Decompression tool
		// Dropped 2nd stage payloads
		$s1 = "@$&%04\\SmartPDF.exe" fullword wide ascii
		$s2 = "@$&%04\\9840432e051a6fa1192594db02b80a4c1fd73456.exe" fullword wide ascii 
		$s3 = "@$&%04\\lg.exe" fullword wide ascii 
		$s4 = "@$&%04\\LivelyScreenRecS3.0.exe" fullword wide ascii
		$s5 = "@$&%04\\note866.exe" fullword wide ascii
		$s6 = "@$&%04\\PBrowFile15.exe" fullword wide ascii
		$s7 = "@$&%04\\stats.exe" fullword wide ascii
		$s8 = "@$&%04\\Visit.url" fullword wide ascii
		$s9 = "@$&%04\\Uninstall.exe" fullword wide ascii
		$s10 = "Inno Setup Setup Data (5.5.7)" fullword wide ascii
		$s11 = "SmartPDF 10.32.0.64.2 Installation" fullword wide ascii
		
	condition:
	uint16(0) == 0x5a4d and any of ($p*) and all of ($s*) // Check first byte (DOS executable)and if it has any of $p and all of $s.
	}