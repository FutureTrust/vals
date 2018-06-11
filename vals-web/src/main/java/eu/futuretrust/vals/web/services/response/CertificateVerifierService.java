package eu.futuretrust.vals.web.services.response;

import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

public interface CertificateVerifierService {

  CertificateVerifier getCertificateVerifier();

  void setCertificateVerifier(final CertificateVerifier certificateVerifier);

  CRLSource getCRLSource();

  void setCRLSource(final CRLSource crlSource);

  OCSPSource getOCSPSource();

  void setOCSPSource(final OCSPSource ocspSource);
}
