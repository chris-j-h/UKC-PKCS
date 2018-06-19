# Unbound Key Control PKCS#11 Extensions

The Unbound PKCS#11 library supports the standard PKCS#11 specifications. It supports PCKS#11 version 2.20, but also includes some of the features of the more advanced versions, 2.30 and 2.40.

The latest version of the PCKS#11 specification can be found here:
 http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html

In addition to the standard, UKC includes some proprietary features, which either reflect advanced crypto mechanisms not yet supported by the standard, or features that are proprietary to UKC.

The associated PKCS#11 extended key types, attributes, and mechanisms are provided in [dy_pkcs11.h](./dy_pkcs11.h) and includes the following:

1.	Proprietary key attributes, such as the key UID or the previous key UID (in case of using the re-key operation).
1.	Advanced symmetric cryptography:
    - AES SIV (https://tools.ietf.org/html/rfc5297).
    - AES XTS (https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS)
1.	Proprietary password protection mechanism.
    
	This option allows you to hash and encrypt a password and do password verification without ever having the password value or the password hash in clear memory. Password validation is done using MPC on the encrypted value, without ever decrypting it.
1.	Software Defined Encryption (SDE) Features.
    
	This UKC component enables different preserving types of encryption, including:
    - MPC based PRF (https://en.wikipedia.org/wiki/Pseudorandom_function_family) for key derivation based on metadata.
    - Functions for size, type and order preserving encryption.

