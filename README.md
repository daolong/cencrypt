

## cencrypt

This is a demo project implement in c language . The demos includes: 

1. How to use openssl encode/decode base64, encrypt/decrypt by rsa/des.
2. How to do http post by libcurl.

All the resources are from Internet.

## How to make

Please install libopenssl and libcurl development package first. 

'make pc=1' will build binary for PC. 

'make' will build binary for arm, but have not test yet. 


Generate key by following commands:

1.  generate private  key                                       
$openssl genrsa -out private.pem 2048

2. view key components                                                
$openssl rsa -text -in private.pem

3. extract public key                                                
$openssl rsa -pubout -in private.pem -out public.pem

4. covert to pkcs8                                                
$openssl pkcs8 -in  private.pem -topk8 -out private.pk8 -nocrypt



