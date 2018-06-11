/*
 * Copyright (c) 2017 European Commission.
 *
 *  Licensed under the EUPL, Version 1.1 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
 *  You may not use this work except in compliance with the Licence.
 *  You may obtain a copy of the Licence at: https://joinup.ec.europa.eu/software/page/eupl5
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 */

package eu.futuretrust.vals.core.etsi.esi.enums;

public enum SubIndication {

  HASH_FAILURE("urn.etsi.019102.subindication.HASH_FAILURE",
      "At least one signed data object (signature, attached document, etc.) that has been included in the signing process does not match the corresponding value in the signature."),
  SIG_CRYPTO_FAILURE("urn.etsi.019102.subindication.SIG_CRYPTO_FAILURE",
      "The signature could not be verified using the signer's certificate."),
  REVOKED("urn.etsi.019102.subindication.REVOKED", "The signing certificate has been revoked."),
  SIG_CONSTRAINTS_FAILURE("urn.etsi.019102.subindication.SIG_CONSTRAINTS_FAILURE",
      "The signature does not match the validation constraints."),
  CHAIN_CONSTRAINTS_FAILURE("urn.etsi.019102.subindication.CHAIN_CONSTRAINTS_FAILURE",
      "The certificate chain used in the validation process does not match the validation constraints related to the certificate."),
  CERTIFICATE_CHAIN_GENERAL_FAILURE("urn.etsi.019102.subindication.CHAIN_CONSTRAINTS_FAILURE",
      "The set of certificates available for chain validation produced an error for an unspecified reason."),
  CRYPTO_CONSTRAINTS_FAILURE("urn.etsi.019102.subindication.CRYPTO_CONSTRAINTS_FAILURE",
      "The signature's cryptographic security level is too low for the validation time."),
  EXPIRED("urn.etsi.019102.subindication.EXPIRED", "The signature is expired."),
  NOT_YET_VALID("urn.etsi.019102.subindication.NOT_YET_VALID", "The signature is not yet valid."),
  FORMAT_FAILURE("urn.etsi.019102.subindication.FORMAT_FAILURE",
      "The format of the signature is not recognized and/or cannot be handled."),
  POLICY_PROCESSING_ERROR("urn.etsi.019102.subindication.POLICY_PROCESSING_ERROR",
      "The signature policy could not be processed."),
  SIGNATURE_POLICY_NOT_AVAILABLE("urn.etsi.019102.subindication.SIGNATURE_POLICY_NOT_AVAILABLE",
      "The signature policy could not be found."),
  TIMESTAMP_ORDER_FAILURE("urn.etsi.019102.subindication.TIMESTAMP_ORDER_FAILURE",
      "Some constraints on the order of time-stamps are not respected."),
  NO_SIGNING_CERTIFICATE_FOUND("urn.etsi.019102.subindication.NO_SIGNING_CERTIFICATE_FOUND",
      "The signing certificate cannot be found or identified."),
  NO_CERTIFICATE_CHAIN_FOUND("urn.etsi.019102.subindication.NO_CERTIFICATE_CHAIN_FOUND",
      "No certificate chain has been found for the identified signing certificate."),
  REVOKED_NO_POE("urn.etsi.019102.subindication.REVOKED_NO_POE",
      "The signature's validity is assumed to be expired. However, the process lacks information about the signing time."),
  REVOKED_CA_NO_POE("urn.etsi.019102.subindication.REVOKED_CA_NO_POE",
      "At least one certificate in the certificate chain is revoked."),
  OUT_OF_BOUNDS_NO_POE("urn.etsi.019102.subindication.OUT_OF_BOUNDS_NO_POE",
      "The signature's validity is assumed to be expired. However, the process lacks information about the signing time."),
  CRYPTO_CONSTRAINTS_FAILURE_NO_POE(
      "urn.etsi.019102.subindication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
      "The signature's cryptographic security level is too low for the validation time. However, the process lacks information about the signing time."),
  NO_POE("urn.etsi.019102.subindication.NO_POE",
      "The process lacks information about the signing time of a signed document."),
  TRY_LATER("urn.etsi.019102.subindication.TRY_LATER",
      "The process lacks information from an external source in order to validate the signature for the moment. You may try again later"),
  SIGNED_DATA_NOT_FOUND("urn.etsi.019102.subindication.SIGNED_DATA_NOT_FOUND",
      "Signed data cannot be obtained."),
  GENERIC("urn.etsi.019102.subindication.GENERIC",
      "The validation failed because of an unspecified reason.");

  private String uri;
  private String message;

  SubIndication(String uri, String message) {
    this.uri = uri;
    this.message = message;
  }

  public String getURI() {
    return this.uri;
  }

  public String getMessage() {
    return message;
  }
}
