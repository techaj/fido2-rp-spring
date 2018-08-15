# Webauthn/FIDO2 Relying Party Reference Implementation
Webauthn/FIDO2 Relying Party Reference Implementation using Springboot and Java.
The implementation is based on code provided in following projects:

[webauthn.bin.coffee](https://github.com/jcjones/webauthn.bin.coffee)

[webauthn-demo](https://github.com/fido-alliance/webauthn-demo)

This is mostly a port from JavaScript into Java/SpringBoot world and in theory you could run on any Pivotal Cloud Foundry certified platform.   

# Requirements
Gradle available on the class path. We have been using version 4.4.

Ideally you would also have a FIDO2 authenticator. We have used  [Yubico Security Key](https://www.yubico.com/product/security-key-by-yubico/).

**We are open to collaboration, if you have FIDO2 authenticator we would like to hear from you.**


Webauthn/FIDO2.0 enabled browser. For a full list of supported browsers see [browser compatibility matrix](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API). 
We have tested with Firefox 60, and Chrome nightly.

Webauthn only works with SecureContext so you might need to generate and configure appropriate certificates and enable TLS. 
See [Generate root cert](generate_keystore.sh) and [Generate RP cert](generate_springboot_keystore.sh) for instructions on how to generate root cert and SSL cert.     

# Running
Adjust properties to ensure that all necessary certs are in correct locations. Yubico root certificate to verify your authenticators is in [./authenticator_certs].

```bash
gradle bootRun
```  

Point your browser at:
https://127.0.0.1:8800/ or even better https://\<your domain\>:8800 

