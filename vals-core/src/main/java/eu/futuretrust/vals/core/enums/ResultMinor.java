/*
 * Copyright (c) 2018 European Commission.
 *
 * Licensed under the EUPL, Version 1.2 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/sites/default/files/inline-files/EUPL%20v1_2%20EN(1).txt
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package eu.futuretrust.vals.core.enums;

public enum ResultMinor
{
  /**
   * If more than one <i>ds:Signature</i> elements are present, the server MUST either reject the
   * request with a <i>ResultMajor</i> code of RequesterError and a <i>ResultMinor</i> code of
   * NotSupported, or accept the request and try to verify all of the signatures. If the server
   * accepts the request in the multi-signature case (or if only a single signature is present) and
   * one of the signatures fails to verify, the server should return one of the error codes,
   * reflecting the first error encountered. If all of the signatures verify correctly, the server
   * should return the Success <i>ResultMajor</i> code and the ValidMultiSignatures
   * <i>ResultMinor</i> code.
   */
  VALID_MULTI_SIGNATURES("urn:oasis:names:tc:dss:1.0:resultminor:ValidMultiSignatures"),

  /**
   * The signature or timestamp is valid. Furthermore, the signature or timestamp covers all of the
   * input documents just as they were passed in by the client.
   */
  ON_ALL_DOCUMENTS("urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments"),

  /**
   * The signature or timestamp is valid. However, the signature or timestamp does not cover all of
   * the input documents that were passed in by the client.
   */
  NOT_ALL_DOCUMENTS_REFERENCED(
          "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:NotAllDocumentsReferenced"),

  /**
   * The signature fails to verify, for example due to the signed document being modified or the
   * incorrect key being used.
   */
  INCORRECT_SIGNATURE("urn:oasis:names:tc:dss:1.0:resultminor:invalid:IncorrectSignature"),

  /**
   * The signature is valid with respect to XML Signature core validation. In addition, the message
   * also contains VerifyManifestResults. Note: In the case that the core signature validation
   * failed no attempt is made to verify the manifest.
   */
  HAS_MANIFEST_RESULTS("urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:HasManifestResults"),

  /**
   * The signature is valid however the timestamp on that signature is invalid
   */
  INVALID_SIGNATURE_TIMESTAMP(
          "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:InvalidSignatureTimestamp"),


  /**
   * A ds:Reference element is present in the ds:Signature containing a full URI, but the
   * corresponding input document is not present in the request.
   */
  REFERENCED_DOCUMENT_NOT_PRESENT(
          "urn:oasis:names:tc:dss:1.0:resultminor:ReferencedDocumentNotPresent"),

  /**
   * The required key information was not supplied by the client, but the server expected it to do
   * so.
   */
  KEY_INFO_NOT_PROVIDED("urn:oasis:names:tc:dss:1.0:resultminor:KeyInfoNotProvided"),

  /**
   * The server was not able to create a signature because more than one RefUri was omitted.
   */
  MORE_THAN_ONE_REF_URI_OMITTED("urn:oasis:names:tc:dss:1.0:resultminor:MoreThanOneRefUriOmitted"),

  /**
   * The value of the RefURIattribute included in an input document is not valid.
   */
  INVALID_REF_URI("urn:oasis:names:tc:dss:1.0:resultminor:InvalidRefURI"),

  /**
   * The server was not able to parse a Document.
   */
  NOT_PARSEABLE_XML_DOCUMENT("urn:oasis:names:tc:dss:1.0:resultminor:NotParseableXMLDocument"),

  /**
   * The server doesn't recognize or can't handle any optional input.
   */
  NOT_SUPPORTED("urn:oasis:names:tc:dss:1.0:resultminor:NotSupported"),

  /**
   * The signature or its contents are not appropriate in the current context.<br>  For example, the
   * signature may be associated with a signature policy and semantics which the DSS server
   * considers unsatisfactory.
   */
  INAPPROPRIATE_SIGNATURE("urn:oasis:names:tc:dss:1.0:resultminor:Inappropriate:signature"),


  /**
   * The processing of the request failed due to an error not covered by the existing error codes.
   * Further details should be given in the result message for the user which may be passed on to
   * the relevant administrator.
   */
  GENERAL_ERROR("urn:oasis:names:tc:dss:1.0:resultminor:GeneralError"),

  /**
   * Locating the identified key failed (e.g. look up failed in directory or in local key file).
   */
  KEY_LOOKUP_FAILED("urn:oasis:names:tc:dss:1.0:resultminor:invalid:KeyLookupFailed"),

  /**
   * The relevant certificate revocation list was not available for checking.
   */
  CRL_NOT_AVAILABLE("urn:oasis:names:tc:dss:1.0:resultminor:CrlNotAvailable"),

  /**
   * The relevant revocation information was not available via the online certificate status
   * protocol.
   */
  OCSP_NOT_AVAILABLE("urn:oasis:names:tc:dss:1.0:resultminor:OcspNotAvailable"),

  /**
   * The chain of trust could not be established binding the public key used for validation to a
   * trusted root certification authority via potential intermediate certification authorities.
   */
  CERTIFICATE_CHAIN_NOT_COMPLETE(
          "urn:oasis:names:tc:dss:1.0:resultminor:CertificateChainNotComplete");

  private String uri;

  ResultMinor(String uri) {
    this.uri = uri;
  }

  public String getURI() {
    return this.uri;
  }

}
