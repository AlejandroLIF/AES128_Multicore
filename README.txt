AES128 Encryption/Decryption Software

Build instructions:
    Run make on the included makefile

Execution instructions:
    The software may run via command-line:
        Usage: AES128.run [-encrypt|-decrypt] [input file] [output file] [32-char HEX Key | 16-char ASCII Key]
        Example: AES128.run -encrypt plaintext.txt encrypted.bin 00112233445566778899AABBCCDDEEFF
        Example: AES128.run -decrypt encrypted.bin plaintext.txt 12345TheKey12345
