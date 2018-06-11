package eu.futuretrust.vals.protocol.enums;

public enum RevocationReason {
  UNSPECIFIED(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:unspecified"),
  KEYCOMPROMISE(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:keyCompromise"),
  CACOMPROMISE(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:cACompromise"),
  AFFILIATIONCHANGED(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:affiliationChanged"),
  SUPERSEDED(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:superseded"),
  CESSATIONOFOPERATION(
      "urn:oasis:names:tc:dssx:1.0:profiles:verificationreport:revocationreason:cessationOfOperation"),
  CERTIFICATEHOLD(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:certificateHold"),
  REMOVEFROMCRL(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:removeFromCRL"),
  PRIVILEGEWITHDRAWN(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:privilegeWithdrawn"),
  AACOMPROMISE(
      "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:revocationreason:aACompromise");

  private String uri;

  RevocationReason(String uri) {
    this.uri = uri;
  }

  public String getURI() {
    return this.uri;
  }

  public static RevocationReason fromURI(String uri) {
    switch (uri) {
      case "unspecified":
        return UNSPECIFIED;
      case "keyCompromise":
        return KEYCOMPROMISE;
      case "cACompromise":
        return CACOMPROMISE;
      case "affiliationChanged":
        return AFFILIATIONCHANGED;
      case "superseded":
        return SUPERSEDED;
      case "cessationOfOperation":
        return CESSATIONOFOPERATION;
      case "certificateHold":
        return CERTIFICATEHOLD;
      case "removeFromCRL":
        return REMOVEFROMCRL;
      case "privilegeWithdrawn":
        return PRIVILEGEWITHDRAWN;
      case "aACompromise":
        return AACOMPROMISE;
      default:
        return null;
    }
  }
}
