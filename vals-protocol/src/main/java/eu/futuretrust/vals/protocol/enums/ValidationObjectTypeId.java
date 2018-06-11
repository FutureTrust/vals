package eu.futuretrust.vals.protocol.enums;

public enum ValidationObjectTypeId {

  CERTIFICATE("urn.etsi.019102.validationObject.certificate"),
  CRL("urn.etsi.019102.validationObject.CRL"),
  OCSPRESPONSE("urn.etsi.019102.validationObject.OCSPResponse"),
  TIMESTAMP("urn.etsi.019102.validationObject.timestamp"),
  EVIDENCERECORD("urn.etsi.019102.validationObject.evidencerecord"),
  PUBLICKEY("urn.etsi.019102.validationObject.publicKey"),
  OTHER("urn.etsi.019102.validationObject.other");

  private String uri;

  ValidationObjectTypeId(String uri) {
    this.uri = uri;
  }

  public String getURI() {
    return this.uri;
  }
}