rule HUNT_Royal_RSA_Public_Key {
	meta:
		description = "Matches an RSA Public Key block found in Royal ransomware Linux samples."
		last_modified = "2024-01-20"
		author = "@petermstewart"
		DaysofYara = "20/100"
		sha256 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"
		sha256 = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"

	strings:
		$key1 = "-----BEGIN RSA PUBLIC KEY-----"
		$key2 = "MIICCAKCAgEAp/24TNvKoZ9rzwMaH9kVGq4x1j+L/tgWH5ncB1TQA6eT5NDtgsQH"
		$key3 = "jv+6N3IY8P4SPSnG5QUBp9uYm3berObDuLURZ4wGW+HEKY+jNht5JD4aE+SS2Gjl"
		$key4 = "+lht2N+S8lRDAjcYXJZaCePN4pHDWQ65cVHnonyo5FfjKkQpDlzbAZ8/wBY+5gE4"
		$key5 = "Tex2Fdh7pvs7ek8+cnzkSi19xC0plj4zoMZBwFQST9iLK7KbRTKnaF1ZAHnDKaTQ"
		$key6 = "uCkJkcdhpQnaDyuUojb2k+gD3n+k/oN33Il9hfO4s67gyiIBH03qG3CYBJ0XfEWU"
		$key7 = "cvvahe+nZ3D0ffV/7LN6FO588RBlI2ZH+pMsyUWobI3TdjkdoHvMgJItrqrCK7BZ"
		$key8 = "TIKcZ0Rub+RQJsNowXbC+CbgDl38nESpKimPztcd6rzY32Jo7IcvAqPSckRuaghB"
		$key9 = "rkci/d377b6IT+vOWpNciS87dUQ0lUOmtsI2LLSkwyxauG5Y1W/MDUYZEuhHYlZM"
		$key10 = "cKqlSLmu8OTitL6bYOEQSy31PtCg2BOtlSu0NzW4pEXvg2hQyuSEbeWEGkrJrjTK"
		$key11 = "v9K7eu+eT5/arOy/onM56fFZSXfVseuC48R9TWktgCpPMkszLmwY14rp1ds6S7OO"
		$key12 = "/HLRayEWjwa0eR0r/GhEHX80C8IU54ksEuf3uHbpq8jFnN1A+U239q0CAQM="
		$key13 = "-----END RSA PUBLIC KEY-----"

	condition:
		filesize > 2MB and filesize < 3MB and
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		all of ($key*)
}
