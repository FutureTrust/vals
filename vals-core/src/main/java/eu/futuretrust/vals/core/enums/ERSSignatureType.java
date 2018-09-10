package eu.futuretrust.vals.core.enums;

public enum ERSSignatureType {

  RFC4998("urn:ietf:rfc:4998"),
  RFC6283("urn:ietf:rfc:6283");

  private String urn;

  ERSSignatureType(String urn) {
    this.urn = urn;
  }

  public String getUrn() {
    return urn;
  }
}
