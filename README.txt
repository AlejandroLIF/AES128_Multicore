AES128 Encryption/Decryption Software

Build instructions:
    Run make on the included makefile

Execution instructions:
    The software may run via command-line:
        Usage: AES128.run [-encrypt|-decrypt] [file] [32-char HEX Key | 16-char ASCII Key]
        Example: AES128.run -encrypt myFile.txt 00112233445566778899AABBCCDDEEFF
        Example: AES128.run -decrypt encrypted.bin 12345TheKey12345
        
    The output is always written to a file named [AES128_encrypted_output | AES128_decrypted_output] and located in the same directory.