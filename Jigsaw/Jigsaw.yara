/*
	Jigsaw Yara Rule
	Author: Martin Georgiev
	Date: 5/3/23
*/

rule Jigsaw_Ransomware {
	meta:
		description = "Yara rule for detecting Jigsaw Ransomware"
		author = "Martin Georgiev"
		university = "Abertay University"
		degree = "BSc Hons Ethical Hacking"
		date = "5/3/23"
		md5 = "2773e3dc59472296cb0024ba7715a64e"
		sha256 = "3ae96f73d805e1d3995253db4d910300d8442ea603737a1428b613061e7f61e7"
		
	strings:
		$s1 = "BitcoinBlackmailer" ascii
		$s2 = "Drpbx\\drpbx.exe" fullword wide ascii // 2nd stage payload #1
		$s3 = "Frfx\\firefox.exe" fullword wide ascii // 2nd stage payload #2
		$s4 = "Try anything funny and the computer has several safety measures to delete your files." fullword wide ascii
		$s5 = "You are about to make a very bad decision. Are you sure about it?" fullword wide ascii
		$s6 = "http://btc.blockr.io/api/v1/" fullword wide // Crypto wallet link part 1
		$s7 = "coin/info/" fullword wide // Crypto wallet link part 2
		$s8 = "coinbase" fullword wide // Crypto wallet link part 3
		$s9 = "address/balance/" fullword wide // Crypto wallet link part 4
		
	condition:
	uint16(0) == 0x5a4d and filesize < 1000KB and all of ($s*) // Check first byte (DOS executable), if under 1000KB and has all of $s 
	}