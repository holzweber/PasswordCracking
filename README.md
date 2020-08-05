# PasswordCracking
This program tries to crack passwords by brute force.
It generates passwords, hashes them, and compares the result to the stored hashes in a password file.
As a second functionality it calculates a line for the password file from a password and an optional salt.

Password creation mode:

The first argument is "-c" to indicate this mode.

The second argument is the username. It must be at least one character long.

The third argument is the password. It must be at least one character long (and at most MAXIMUM_UPPER=5 characters).

The fourth argument is the hashing algorithm. Either "SHA1" or "SHA2".

The fifth argument is optional and is the salt in hexadecimal encoding. If present, it may be up to 10 bytes long (=20 characters). If absent or too short, the salt to be used is filled to the right with zero bytes.

Example invocations of your program might look like this:

./crack -c michael1 12345 SHA1
./crack -c michael2 12345 SHA2 1234567890ABCDEF
see files

Password breaking mode:

The first argument is "-b" to indicate this mode.

The second argument is optional "-t" to indicate that the time should be measured.

The second/third argument is the name of the password file.

The third/fourth argument is the minimum length of passwords to try. Must be between 1 and 4.

The fourth/fifth argument is the maximum length of passwords to try. Must be between 1 and 5.

Example invocations of your program might look like this:

./crack -b -t hashes.txt 1 3
./crack -b hashes.txt 4 5
see files
This project is based to run on a Linux operating system


The program supports two different hash functions. For the actual implementation you must use the openssl library (libcrypto: https://www.openssl.org/docs/manmaster/crypto/crypto.html; see here for the hashing functions). 

