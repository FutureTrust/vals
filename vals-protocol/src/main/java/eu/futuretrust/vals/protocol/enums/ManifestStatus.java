package eu.futuretrust.vals.protocol.enums;

public enum ManifestStatus {

  /**
   * The manifest reference is valid
   */
  VALID("urn:oasis:names:tc:dss:1.0:manifeststatus:Valid"),

  /**
   * The manifest reference is invalid
   */
  INVALID("urn:oasis:names:tc:dss:1.0:manifeststatus:Invalid");

  private String uri;

  ManifestStatus(String uri) {
    this.uri = uri;
  }

  public String getURI() {
    return this.uri;
  }

}
