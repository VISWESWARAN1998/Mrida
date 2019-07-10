/*
	SWAMI KARUPPASWAMI THUNNAI
*/


rule memz 
{
   meta:
      author = "Visweswaran N"
	   description = "Detecting Memz trojan"
      md5 = "19DBEC50735B5F2A72D4199C4E184960"

   strings:
      $s1 = "DO YOU WANT TO EXECUTE THIS MALWARE"
	   $s2 = "This malware will harm your computer and makes it unusable"

   condition:
      all of them
}