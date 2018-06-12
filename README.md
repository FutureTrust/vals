# The Comprehensive Validation Service

The Comprehensive Validation Service is essentially a software library enabling application developers to call specific functionalities for the validation of signed artefacts.
It also includes a light web application that exposes a RESTful interface through which these functionalities can be called.

The Comprehensive Validation Service implements the OASIS DSS verification protocol and, more specifically, the following profiles:
* The DSS Core profile, which provides the core elements of the protocol and is used by default when no specific profile is specified by the user requesting the verification of a signed artifact;
* The DSS-X multi-signature verification report profile, which allows users to request the generation of a detailed validation report;
* The DSS-X signature policy profile, which defines specific elements for providing a Policy that should be applied for the validation of an electronic signature;
* The DSS JWS Digital Signature profile, which defines the elements necessary for requesting the verification of JSON Web Signatures as defined in RFC 7515;
* The DSS Evidence Record verification profile, which defines the elements to specify when requesting the verification of an Evidence Record (either compliant with RFC 4998 - CMS/ASN.1 - or RFC 6283 - XML);
* The DSS Asynchronous profile, which defines the elements to specify when requesting the verification of a signed artifact in an asynchronous manner;
* The DSS Entity seal profile, which documents the use of the DSS core elements for the validation of electronic seals (i.e. signatures generated with a certificate tied to a legal entity);
* The DSS AdES profile, which provides the specific elements required for the validation of XAdES an CAdES signatures.

Additionally, the Comprehensive Validation Service also partially implements the ETSI 119 102-2 and 119 442 draft standards which specify, respectively:
* The structure and contents of the validation reports to be returned by trust services providing signature validation services;
* The protocol for accessing trust services providing signature validation services. This protocol is based on the OASIS DSS protocol, and extends it to support PAdES signatures. In the case of the Comprehensive Validation Service, this protocol was extended further to support ASiC-S and ASiC-E containers.

## Code Organisation
The source code of the Comprehensive Validation Service is organised as follows:
* The vals-common module contains utility classes used by other modules;
* The vals-core module contains the core validation logic for the signed artefacts that the library can process and validate;
* The vals-policy module contains the logic associated with the processing of validation policies;
* The vals-jaxb module contains all classes that were automatically generated from existing schemas;
* The vals-protocol module contains the logic implementing the validation protocol defined in OASIS DSS;
* The vals-web module contains the SpringBoot web application exposing a RESTful validation interface. 

## Compiling the modules
Besides the vals-web module, the other modules do not require any specific configuration.
For the vals-web module, the property files provided under the src/main/resources folder must be edited in order to match the local configuration:
* The application.properties file currently has only a single property (unused at the moment), which is the URL of the GTSL end-point that must be contacted in order to retrieve trust status information related to a given electronic certificate;
* The crypto.properties file contains all properties related to trust anchors, TSL certificates etc.;
* The policy.properties files contains the properties related to the validation policy used in the validation process. 

## REST API Examples
Assuming that the vals-web application has been successfully deployed and is listening on port 80, the following cURL request can be sent in order to trigger the validation of an electronic signature:

admin@localhost# curl -X POST http://vals-test.futuretrust.eu/api/validation -H "Content-Type: application/xml" -H "Accept: application/xml" --data "@verify-request.xml" > verify-response.xml

Note that this command:
* Requests the validation of an electronic signature by sending a VerifyRequest in XML form (cfr. the Content-type HTTP header), compliant with the VerifyRequest element defined in OASIS DSS;
* Requests that the VerifyResponse returned by the server is provided in XML form as well (cfr. the Accept HTTP header);

If either the request or the response must be sent/returned in JSON, the corresponding HTTP header must be adapted.