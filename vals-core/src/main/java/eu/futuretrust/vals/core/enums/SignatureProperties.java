package eu.futuretrust.vals.core.enums;

public enum SignatureProperties {

  XMLDSIG_SIGNATURE_PROPERTIES("http://www.w3.org/2000/09/xmldsig#SignatureProperties"),
  ETSI_SIGNATURE_PROPERTIES("http://uri.etsi.org/01903#SignedProperties");

  private final String type;

  SignatureProperties(String type) {
    this.type = type;
  }

  public static boolean contains(String type) {
    for (SignatureProperties c : SignatureProperties.values()) {
      if (c.type.equals(type)) {
        return true;
      }
    }
    return false;
  }
}
