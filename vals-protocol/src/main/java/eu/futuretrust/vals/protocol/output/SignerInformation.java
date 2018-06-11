package eu.futuretrust.vals.protocol.output;


public class SignerInformation {

  private String countryName;
  private String organizationName;
  private String distinguishedName;
  private String pseudonym;
  private byte[] base64Encoded;

  public SignerInformation() {
  }

  public SignerInformation(byte[] base64Encoded) {
    this.base64Encoded = base64Encoded;
  }

  public String getDistinguishedName() {
    return distinguishedName;
  }

  public void setDistinguishedName(String commonName) {
    this.distinguishedName = commonName;
  }

  public byte[] getBase64Encoded() {
    return base64Encoded;
  }

  public void setBase64Encoded(byte[] base64Encoded) {
    this.base64Encoded = base64Encoded;
  }

  public String getCountryName() {
    return countryName;
  }

  public void setCountryName(String countryName) {
    this.countryName = countryName;
  }

  public String getOrganizationName() {
    return organizationName;
  }

  public void setOrganizationName(String organizationName) {
    this.organizationName = organizationName;
  }

  public String getPseudonym() {
    return pseudonym;
  }

  public void setPseudonym(String pseudonym) {
    this.pseudonym = pseudonym;
  }
}
