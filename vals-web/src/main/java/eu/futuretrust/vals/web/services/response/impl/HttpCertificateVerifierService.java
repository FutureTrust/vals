package eu.futuretrust.vals.web.services.response.impl;

import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.futuretrust.vals.protocol.output.Certificate;
import eu.futuretrust.vals.web.properties.CryptoProperties;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

@Log
@Service
public class HttpCertificateVerifierService implements CertificateVerifierService
{

  private CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
  private CryptoProperties cryptoProperties;


  @Autowired
  public HttpCertificateVerifierService(CryptoProperties cryptoProperties) {
    this.cryptoProperties = cryptoProperties;
    this.certificateVerifier.setDataLoader(new NativeHTTPDataLoader());
    this.certificateVerifier.setOcspSource(new OnlineOCSPSource());
    this.certificateVerifier.setCrlSource(new OnlineCRLSource(new NativeHTTPDataLoader()));
    this.certificateVerifier.setIncludeCertificateTokenValues(true);
    this.certificateVerifier.setIncludeCertificateRevocationValues(true);
    addTrustedCertificates();
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

  private void addTrustedCertificates()
  {
    this.certificateVerifier.createValidationPool();

    if (this.certificateVerifier.getTrustedCertSource() == null) {
      this.certificateVerifier.setTrustedCertSource(new CommonCertificateSource());
    }
    if (this.certificateVerifier.getGtslCertSource() == null) {
      this.certificateVerifier.setGtslCertSource(new CommonCertificateSource());
    }

    for (final CertificateToken token : getLocalTrustedSource().getCertificates())
    {
      this.certificateVerifier.getTrustedCertSource().addCertificate(token);
    }
    for (final CertificateToken token : getTslTrustedSource().getCertificates())
    {
      this.certificateVerifier.getGtslCertSource().addCertificate(token);
    }

    log.info("Done loading local trust sources");
  }

  private KeyStoreCertificateSource getLocalTrustedSource()
  {
    final String keystorePath = cryptoProperties.getLocalKeystorePath();
    final String keystorePassword = cryptoProperties.getLocalKeystorePassword();
    if (StringUtils.isNotEmpty(keystorePath) && StringUtils.isNotEmpty(keystorePassword)) {
      final FileInputStream keystoreIS;
      try
      {
        keystoreIS = new FileInputStream(new File(keystorePath));
        return new KeyStoreCertificateSource(keystoreIS, cryptoProperties.getKeystoreType(),
                keystorePassword);
      } catch (FileNotFoundException e)
      {
        log.info("Failed to load local trust source");
      }
    }
    return null;
  }

  private KeyStoreCertificateSource getTslTrustedSource()
  {
    final String keystorePath = cryptoProperties.getKeystorePath();
    final String keystorePassword = cryptoProperties.getKeystorePassword();

    final FileInputStream keystoreIS;
    try
    {
      keystoreIS = new FileInputStream(new File(keystorePath));
      return new KeyStoreCertificateSource(keystoreIS, cryptoProperties.getKeystoreType(),
              keystorePassword);
    } catch (FileNotFoundException e)
    {
      log.info("Failed to load TSL trust source");
    }
    return null;
  }
}
