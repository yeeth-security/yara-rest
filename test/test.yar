/*
 * EICAR Test Signature Rule
 * 
 * This is a TEST RULE ONLY - used to verify YARA scanning is working.
 * 
 * The EICAR test file is a standard, harmless file used to test antivirus
 * and malware scanning software. It is NOT malicious - it's specifically
 * designed to trigger detection without causing any harm.
 * 
 * EICAR string: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
 * 
 * See: https://www.eicar.org/download-anti-malware-testfile/
 */

rule EICAR_Test_Signature {
    meta:
        description = "Detects the EICAR antivirus test file"
        severity = "low"
        author = "test"
        reference = "https://www.eicar.org/"
        is_test_rule = true
    
    strings:
        // The standard EICAR test string
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    condition:
        $eicar
}
