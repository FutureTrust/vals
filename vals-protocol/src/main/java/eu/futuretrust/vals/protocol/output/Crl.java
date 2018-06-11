package eu.futuretrust.vals.protocol.output;


import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CRLValidityType;

public class Crl {

  private final byte[] base64;
  private final CRLValidityType validity;

  public Crl(final byte[] base64, final CRLValidityType validity) {
    this.base64 = base64;
    this.validity = validity;
  }

  public CRLValidityType getValidity() {
    return validity;
  }

  public byte[] getBase64() {
    return base64;
  }
}
