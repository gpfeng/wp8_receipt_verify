# wp8_receipt_verify
Windonws phone 8 in-app-purchase receipt verification with Golang


## There are 2 problems to verify winodws phone 8 receipt with Golang:

*	The serial number of IapReceiptProduction.cer is negative, which will lead to certificate parsing failure with Golang x509 package
*	XML Digital Signature is used for receipt verification, which is really complicated, while Golang DO NOT have the related libraries to handle this 

For the 1st problem, there are 2 solutions:
1. wrap the x509 package to ignore the "negative serial number" error
2. extract public key form the certification using openssl or key chain

For the 2nd problem, I have searched many golang and xml digital signature related repos in github and finally find [amdonov/xmlsig](https://github.com/amdonov/xmlsig), which helps a lot.

### Want to know more?
Code says everything