package eu.futuretrust.vals.web.services.response.impl;

import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import org.springframework.stereotype.Service;

@Service
public class HttpCertificateVerifierService implements CertificateVerifierService
{

  private CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

  public HttpCertificateVerifierService() {

    this.certificateVerifier.setDataLoader(new NativeHTTPDataLoader());
    this.certificateVerifier.setOcspSource(new OnlineOCSPSource());
    this.certificateVerifier.setCrlSource(new OnlineCRLSource(new NativeHTTPDataLoader()));
  }

  @Override
  public CertificateVerifier getCertificateVerifier()
  {
    return certificateVerifier;
  }

  @Override
  public void setCertificateVerifier(CertificateVerifier certificateVerifier)
  {
    this.certificateVerifier = certificateVerifier;
  }

  @Override
  public CRLSource getCRLSource()
  {
    return certificateVerifier.getCrlSource();
  }

  @Override
  public void setCRLSource(CRLSource crlSource)
  {
    this.certificateVerifier.setCrlSource(crlSource);
  }

  @Override
  public OCSPSource getOCSPSource()
  {
    return certificateVerifier.getOcspSource();
  }

  @Override
  public void setOCSPSource(OCSPSource ocspSource)
  {
    this.certificateVerifier.setOcspSource(ocspSource);
  }
}
