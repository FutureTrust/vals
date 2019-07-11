package eu.futuretrust.vals.web.services.response.impl;

import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.x509.crl.ListCRLSource;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.protocol.exceptions.KeystoreLoadingException;
import eu.futuretrust.vals.web.properties.CryptoProperties;
import eu.futuretrust.vals.web.services.gtls.GTSLCertificateSource;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

@Service
public class CertificateVerifierServiceImpl implements CertificateVerifierService {

  private final static Logger LOGGER = LoggerFactory.getLogger(CertificateVerifierServiceImpl.class);
  private static final String LOTL_ROOT_SCHEME_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl.html";
  private static final String LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
  private static final String LOTL_ISO_CODE = "EU";
  private static final String OJ_URL = "http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG";

  private CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
  private Date refreshDate;
  private CryptoProperties cryptoProperties;
  private String gtslEndpointUrl;

  @Autowired
  public CertificateVerifierServiceImpl(CryptoProperties cryptoProperties,
                                        @Value("${vals.gtslEndpoint}") String gtslEndpointUrl) {
    this.cryptoProperties = cryptoProperties;
    this.certificateVerifier.setDataLoader(new CommonsDataLoader());
    this.certificateVerifier.setOcspSource(new OnlineOCSPSource());
    CRLSource crlSource = new OnlineCRLSource(new CommonsDataLoader());
    this.certificateVerifier.setCrlSource(crlSource);
    this.gtslEndpointUrl = gtslEndpointUrl;

    if (StringUtils.isNotEmpty(cryptoProperties.getCrlSourceFolderPath())) {
      CRLSource crlSource = getOfflineCRLSource();
      this.certificateVerifier.setCrlSource(crlSource);
      if (crlSource instanceof OfflineCRLSource) {
        this.certificateVerifier.setSignatureCRLSource(new ListCRLSource((OfflineCRLSource) crlSource));
      }
    } else {
      CRLSource crlSource = new OnlineCRLSource(new CommonsDataLoader());
      this.certificateVerifier.setCrlSource(crlSource);
    }
    try {
      initTrustedCertSource();
    } catch (KeystoreLoadingException e) {
      e.printStackTrace();
    }
  }

  @Override
  public CertificateVerifier getCertificateVerifier() {
    return certificateVerifier;
  }

  @Override
  public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
    this.certificateVerifier = certificateVerifier;
  }

  @Override
  public CRLSource getCRLSource() {
    return certificateVerifier.getCrlSource();
  }

  @Override
  public void setCRLSource(CRLSource crlSource) {
    certificateVerifier.setCrlSource(crlSource);
  }

  @Override
  public OCSPSource getOCSPSource() {
    return certificateVerifier.getOcspSource();
  }

  @Override
  public void setOCSPSource(OCSPSource ocspSource) {
    certificateVerifier.setOcspSource(ocspSource);
  }

  public void initTrustedCertSource() throws KeystoreLoadingException {

    final TrustedListsCertificateSource certificateSource = new TrustedListsCertificateSource();
    final TSLRepository tslRepository = new TSLRepository();
    tslRepository.setTrustedListsCertificateSource(certificateSource);

    // Load the TL in a temp file, to load the trusted certificates...
    FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
    File cacheFolder;

    cacheFolder = new File(cryptoProperties.getTslCachePath());
    fileCacheDataLoader.setFileCacheDirectory(cacheFolder);

    TSLValidationJob job = new TSLValidationJob();
    job.setDataLoader(new CommonsDataLoader());
    try {
      job.setOjContentKeyStore(getTslValidationKeystore());
    } catch (IOException e) {
      throw new KeystoreLoadingException("Unable to load keystore", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    job.setLotlRootSchemeInfoUri(LOTL_ROOT_SCHEME_URL);
    job.setLotlUrl(LOTL_URL);
    job.setOjUrl(OJ_URL);
    job.setLotlCode(LOTL_ISO_CODE);
    job.setRepository(tslRepository);
    job.initRepository();

    if (refreshDate == null) {
      refreshDate = new Date();
      job.refresh();
    }

    //todo: extract and make configurable
    if (((new Date()).getTime() - refreshDate.getTime()) >= 1000 * 60 * 60 * 24) {
      refreshDate = new Date();
      job.refresh();
    }
    try {
      KeyStoreCertificateSource keyStoreCertificateSource = getLocalTrustedSource();
      if (keyStoreCertificateSource != null) {
        ServiceInfo serviceInfo = new ServiceInfo();
        for (CertificateToken certificateToken : keyStoreCertificateSource.getCertificates()) {
          certificateSource.addCertificate(certificateToken, serviceInfo);
        }
      }
    } catch (Exception e) {
      LOGGER.warn("Failed to load local keystore certificates: %s", e);
    }
    certificateVerifier.setTrustedCertSource(certificateSource);
    certificateVerifier.setDataLoader(fileCacheDataLoader);
    if (StringUtils.isNotEmpty(gtslEndpointUrl)) {
        certificateVerifier.setGtslCertSource(new GTSLCertificateSource(gtslEndpointUrl));
    }
  }

  private KeyStoreCertificateSource getTslValidationKeystore() throws IOException {
    final String keystorePath = cryptoProperties.getKeystorePath();
    final String keystorePassword = cryptoProperties.getKeystorePassword();

    final FileInputStream keystoreIS = new FileInputStream(new File(keystorePath));
    return new KeyStoreCertificateSource(keystoreIS, cryptoProperties.getKeystoreType(),
        keystorePassword);
  }

  private KeyStoreCertificateSource getLocalTrustedSource() throws IOException {
    final String keystorePath = cryptoProperties.getLocalKeystorePath();
    final String keystorePassword = cryptoProperties.getLocalKeystorePassword();
    if (StringUtils.isNotEmpty(keystorePath) && StringUtils.isNotEmpty(keystorePassword)) {
      final FileInputStream keystoreIS = new FileInputStream(new File(keystorePath));
      return new KeyStoreCertificateSource(keystoreIS, cryptoProperties.getKeystoreType(),
          keystorePassword);
    }
    return null;
  }

  private CRLSource getOfflineCRLSource() {
    try {
      List<InputStream> crlISList = new ArrayList<>();
      try (Stream<Path> paths = Files.walk(Paths.get(cryptoProperties.getCrlSourceFolderPath()))) {
        paths.filter(Files::isRegularFile).forEach(path -> {
          try {
            InputStream is = new FileInputStream(path.toFile());
            crlISList.add(is);
          } catch (FileNotFoundException e) {
            LOGGER.error("Unable to read CRL file %s: %s", path.toAbsolutePath(), e);
          }
        });
      }
      InputStream[] inputStreams = new InputStream[crlISList.size()];
      crlISList.toArray(inputStreams);
      return new ExternalResourcesCRLSource(inputStreams);
    } catch (Exception e) {
      return new OnlineCRLSource(new CommonsDataLoader());
    }
  }
}
