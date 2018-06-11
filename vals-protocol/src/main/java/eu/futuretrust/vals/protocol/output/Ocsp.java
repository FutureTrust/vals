package eu.futuretrust.vals.protocol.output;


import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.OCSPValidityType;

public class Ocsp {
  private final byte[] base64;
  private final OCSPValidityType validity;

  public Ocsp(final byte[] base64,
      final OCSPValidityType validity) {
    this.base64 = base64;
    this.validity = validity;
  }

  public OCSPValidityType getValidity() {
    return validity;
  }

  public byte[] getBase64() {
    return base64;
  }

}
