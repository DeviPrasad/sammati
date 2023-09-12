# Background
https://sahamati.gitbook.io/security-standards/background

# create unique identifier representing Sammati account aggregator entiry
A string identifier will be used to represent Sammati-AA. This identifier is embedded in some notifications sent to FIUs and AA client.

# have an abstraction to create and process timestamps in ISO 8601 format.
YYYY-MM-DDThh-mm-ss-xxxZ


# Request for Comments: 4492
Key Exchange Algorithm        Description
-----------------------       ------------
ECDH_ECDSA                    Fixed ECDH with ECDSA-signed certificates.
ECDHE_ECDSA                   Ephemeral ECDH with ECDSA signatures.

The ECDHE_ECDSA key exchange mechanisms provide forward secrecy.


JSON Web Signature and Detached Content/Signature
JSON Web Signature (JWS)
https://www.rfc-editor.org/rfc/rfc7515.txt

Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
https://datatracker.ietf.org/doc/html/rfc7520
