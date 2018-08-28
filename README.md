# Webauthn/FIDO2 Relying Party Reference Implementation
Webauthn/FIDO2 Relying Party Reference Implementation using Springboot and Java.
The implementation was originally based on code provided in following projects:

[webauthn.bin.coffee](https://github.com/jcjones/webauthn.bin.coffee)

[webauthn-demo](https://github.com/fido-alliance/webauthn-demo)

But since then this has been re-written and improved. The project has been tested against FIDO2 Conformance tools and there has been a clean run against FIDO Conformance Tools v0.10.109.
[See results here](./other/FIDOConfTool-0.10.109.png)

   

# Requirements
Gradle available on the class path. We have been using version 4.4.

Ideally you would also have a FIDO2 authenticator. We have used  [Yubico Security Key](https://www.yubico.com/product/security-key-by-yubico/).

**We are open to collaboration, if you have FIDO2 authenticator we would like to hear from you.**


Webauthn/FIDO2.0 enabled browser. For a full list of supported browsers see [browser compatibility matrix](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API). 
We have tested with Firefox 60, and Chrome nightly.

Webauthn only works with SecureContext so you might need to generate and configure appropriate certificates and enable TLS. 
See [Generate root cert](generate_keystore.sh) and [Generate RP cert](generate_springboot_keystore.sh) for instructions on how to generate root cert and SSL cert.     


# Running against FIDO Conformance Tool
In order to run against the certification you will need to 
 * Change the RP domain name **rp.domain**. For time being this is case sensitive and it has to match the test tool configuration.
 * Disable SSL  
 * FIDO2 Conformance Tool metadata in **server.metadata.folder**  
 * Register your domain with FIDO2 MDS test service **mds.service.url**
 * Download all TOC files and put them in **mds.toc.files.folder**
 * Download root certificate to verify TOC files and put in **mds.toc.root.file.location**
 
 ```bash
 gradle bootRun
 ```
 
 
# Normal operation 
Adjust properties to ensure that all necessary certs are in correct locations. Yubico root certificate to verify your authenticators is in [./authenticator_certs].
You will need to point at read MDS service (still work in progress as you will need to obtain the authorization code and some real authenticators) or copy necessary metadata to **server.metadata.folder**


Point your browser at:
https://127.0.0.1:8800/ or even better https://\<your domain\>:8800 

 
