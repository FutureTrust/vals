package eu.futuretrust.vals.protocol.output;


import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignedPropertiesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.UnsignedPropertiesType;

public class SignatureAttributes {

  SignedPropertiesType signedProperties;
  UnsignedPropertiesType unsignedProperties;

  public SignatureAttributes() {
  }

  public SignatureAttributes(
      SignedPropertiesType signedProperties) {
    this.signedProperties = signedProperties;
  }

  public SignatureAttributes(
      UnsignedPropertiesType unsignedProperties) {
    this.unsignedProperties = unsignedProperties;
  }

  public SignatureAttributes(
      SignedPropertiesType signedProperties,
      UnsignedPropertiesType unsignedProperties) {
    this.signedProperties = signedProperties;
    this.unsignedProperties = unsignedProperties;
  }

  public SignedPropertiesType getSignedProperties() {
    return signedProperties;
  }

  public void setSignedProperties(
      SignedPropertiesType signedProperties) {
    this.signedProperties = signedProperties;
  }

  public UnsignedPropertiesType getUnsignedProperties() {
    return unsignedProperties;
  }

  public void setUnsignedProperties(
      UnsignedPropertiesType unsignedProperties) {
    this.unsignedProperties = unsignedProperties;
  }
}
