package eu.futuretrust.vals.protocol.validation.validity;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificatePathValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.VerificationResultType;
import eu.futuretrust.vals.jaxb.oasis.xmldsig.core.X509IssuerSerialType;
import java.math.BigInteger;

/**
 * A DSSCertificatePathValidityParser is an object which proposes to parse the
 * CertificatePathValidity of a CertificateWrapper
 */
public class DSSCertificatePathValidityParser {

  private CertificatePathValidityType certificatePathValidityType;
  private CertificateWrapper certificateWrapper;

  public DSSCertificatePathValidityParser(CertificateWrapper certificateWrapper) {
    this.certificateWrapper = certificateWrapper;
    this.certificatePathValidityType = new CertificatePathValidityType();
  }

  public CertificatePathValidityType getCertificatePathValidityType() {
    // x509IssuerSerialType contains a unique reference to the certificate whose path has been checked.
    X509IssuerSerialType x509IssuerSerialType = new X509IssuerSerialType();
    x509IssuerSerialType.setX509IssuerName(certificateWrapper.getCertificateIssuerDN());
    x509IssuerSerialType
        .setX509SerialNumber((new BigInteger(certificateWrapper.getSerialNumber())));
    certificatePathValidityType.setCertificateIdentifier(x509IssuerSerialType);

    // pathValiditySummary contains a summary of the result of the certificate path validation.
    VerificationResultType pathValiditySummary = new VerificationResultType();
    if (certificateWrapper.isRevoked()) {
      pathValiditySummary.setResultMajor(MainIndication.TOTAL_FAILED.getURI());
    } else {
      pathValiditySummary.setResultMajor(MainIndication.TOTAL_PASSED.getURI());
    }
    certificatePathValidityType.setPathValiditySummary(pathValiditySummary);
    return certificatePathValidityType;
  }


}
