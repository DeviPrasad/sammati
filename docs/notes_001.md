
A message digest is a fixed size numeric representation of the contents of a message, computed by a hash function.
Messages vary in size. A message digest is a fixed size numeric representation of the contents of a message. A message digest is computed by a one-way hash function.

A message digest can be encrypted, forming a digital signature.

The message digest is sent with the message itself. The receiver can generate a digest for the message and compare it with the digest of the sender. The integrity of the message is verified when the two message digests are the same. Any tampering with the message during transmission almost certainly results in a different message digest.

A message digest created using a secret symmetric key is known as a Message Authentication Code (MAC).

The sender can encrypt the digest using the private key of an asymmetric key pair, forming a digital signature. The signature must then be decrypted by the receiver, before comparing it with a locally generated digest.
