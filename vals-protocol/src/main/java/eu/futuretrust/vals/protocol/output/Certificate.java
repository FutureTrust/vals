package eu.futuretrust.vals.protocol.output;

import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateValidityType;
import java.util.Set;

public class Certificate {

  private final byte[] base64;
  private final CertificateValidityType validity;
  private final Set<RevocationWrapper> revocationData;

  public Certificate(final byte[] base64,
      final CertificateValidityType validity,
      final Set<RevocationWrapper> revocationData) {
    this.base64 = base64;
    this.validity = validity;
    this.revocationData = revocationData;
  }

  public byte[] getBase64() {
    return base64;
  }

  public CertificateValidityType getValidity() {
    return validity;
  }

  public Set<RevocationWrapper> getRevocationData() {
    return revocationData;
  }
}
