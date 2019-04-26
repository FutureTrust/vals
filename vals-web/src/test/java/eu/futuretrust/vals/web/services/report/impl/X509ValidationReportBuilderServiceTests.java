package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;
import eu.europa.esig.dss.x509.crl.ExternalResourcesCRLSource;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.OptionalInputsVerifyType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.InputDocumentsType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.SignatureObjectType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.UseVerificationTimeType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import eu.futuretrust.vals.web.properties.CryptoProperties;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import eu.futuretrust.vals.web.services.response.impl.CertificateVerifierServiceImpl;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;

public class X509ValidationReportBuilderServiceTests
{

  private final static String TEST_ROOT_CRL_PATH = "x509/root_crl.pem";
  private final static String TEST_CA_CRL_PATH = "x509/ca_crl.pem";
  private final static String TSL_VALIDATION_KEYSTORE = "x509/trustStore.p12";
  private final static String TSL_PASSWORD = "dss-password";
  private final static String TSL_KEYSTORE_TYPE = "PKCS12";
  private final static String TEST_CA_PATH = "x509/vals_ca.cer";
  private final static String TEST_ROOT_PATH = "x509/vals_root.cer";
  private final static String ON_HOLD_CERT_PATH = "x509/vals_onhold.cer";
  private final static String REVOKED_CERT_PATH = "x509/vals_revoked.cer";
  private final static String VALID_CERT_PATH = "x509/vals_valid.cer";
  private final static String NOT_YET_VALID_CERT_PATH = "x509/vals_not_yet_valid.cer";
  private final static String EXPIRED_CERT_PATH = "x509/vals_expired.cer";
  private final static String SELF_SIGNED_CERT_PATH = "x509/vals_self_signed.cer";

  private final static String DSS_POLICY_PATH = "policy/dss-default-policy.xml";

  private CertificateVerifierService certificateVerifierService;

  private X509ValidationReportBuilderServiceImpl reportBuilderService;
  private CertificateVerifier verifier;

  private Policy policy;

  @Before
  public void init() throws CertificateException, IOException
  {
    final ClassLoader classLoader = this.getClass().getClassLoader();

    InputStream rootCrlIS = classLoader.getResourceAsStream(TEST_ROOT_CRL_PATH);
    InputStream caCrlIS = classLoader.getResourceAsStream(TEST_CA_CRL_PATH);
    final CryptoProperties properties = new CryptoProperties();
    properties.setTslCachePath("/tmp/tsl/cache");
    properties.setKeystorePath(classLoader.getResource(TSL_VALIDATION_KEYSTORE).getPath());
    properties.setKeystorePassword(TSL_PASSWORD);
    properties.setKeystoreType(TSL_KEYSTORE_TYPE);

    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    X509Certificate caCert = (X509Certificate) factory.generateCertificate(classLoader.getResourceAsStream(TEST_CA_PATH));
    X509Certificate rootCert = (X509Certificate) factory.generateCertificate(classLoader.getResourceAsStream(TEST_ROOT_PATH));

    certificateVerifierService = new CertificateVerifierServiceImpl(properties);
    verifier = new CommonCertificateVerifier();
    CertificateSource trustedSource = new CommonCertificateSource();
    trustedSource.addCertificate(new CertificateToken(caCert));
    trustedSource.addCertificate(new CertificateToken(rootCert));
    verifier.setTrustedCertSource(trustedSource);
    final ExternalResourcesCRLSource crlSource = new ExternalResourcesCRLSource(rootCrlIS, caCrlIS);
    verifier.setCrlSource(crlSource);

    certificateVerifierService.setCertificateVerifier(verifier);

    final File policyFile = new File(classLoader.getResource(DSS_POLICY_PATH).getFile());
    policy = new Policy("https://test.url.eu/policy/dss-policy.xml", Files.readAllBytes(policyFile.toPath()));

    reportBuilderService = new X509ValidationReportBuilderServiceImpl(certificateVerifierService);
  }

  @Test
  public void testStatusOnHold() throws IOException
  {
    VerifyRequestType verifyRequest = buildVerifyRequest(ON_HOLD_CERT_PATH);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:certificate:onHold", report.getResult().getResultMinor());
  }

  @Test
  public void testStatusRevoked() throws IOException
  {
    VerifyRequestType verifyRequest = buildVerifyRequest(REVOKED_CERT_PATH);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:certificate:revoked", report.getResult().getResultMinor());
  }

  @Test
  public void testStatusNotValidYet() throws IOException
  {
    VerifyRequestType verifyRequest = buildVerifyRequest(VALID_CERT_PATH);
    UseVerificationTimeType useVerificationTimeType = new UseVerificationTimeType();
    useVerificationTimeType.setSpecificTime(XMLGregorianCalendarBuilder.createXMLGregorianCalendar(new Date(1428841824000l)));
    OptionalInputsVerifyType optionalInputsVerifyType = new OptionalInputsVerifyType();
    optionalInputsVerifyType.setUseVerificationTime(useVerificationTimeType);
    verifyRequest.setOptionalInputs(optionalInputsVerifyType);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:certificate:notValidYet", report.getResult().getResultMinor());
  }

  @Test
  public void testStatusExpired() throws IOException
  {
    VerifyRequestType verifyRequest = buildVerifyRequest(EXPIRED_CERT_PATH);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:certificate:expired", report.getResult().getResultMinor());
  }

  @Test
  public void testUseVerificationTime() throws IOException
  {
    VerifyRequestType verifyRequest = buildVerifyRequest(EXPIRED_CERT_PATH);
    UseVerificationTimeType useVerificationTimeType = new UseVerificationTimeType();
    useVerificationTimeType.setSpecificTime(XMLGregorianCalendarBuilder.createXMLGregorianCalendar(new Date(1428841824000l)));
    OptionalInputsVerifyType optionalInputsVerifyType = new OptionalInputsVerifyType();
    optionalInputsVerifyType.setUseVerificationTime(useVerificationTimeType);
    verifyRequest.setOptionalInputs(optionalInputsVerifyType);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments", report.getResult().getResultMinor());
  }

  @Test
  public void testCertificateChainIncomplete() throws IOException
  {
    VerifyRequestType verifyRequest = buildVerifyRequest(SELF_SIGNED_CERT_PATH);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:CertificateChainNotComplete", report.getResult().getResultMinor());
  }

  @Test
  public void testCertificateValid() throws IOException
  {
    VerifyRequestType verifyRequest = buildVerifyRequest(VALID_CERT_PATH);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments", report.getResult().getResultMinor());
  }

  @Test
  public void testVerifyRequestInvalidWrongMimetype() throws IOException
  {
    VerifyRequestType verifyRequest = buildInvalidMimeTypeVerifyRequest(VALID_CERT_PATH);
    SignedObject signedObject = buildInvalidMimeTypeSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError", report.getResult().getResultMajor());
  }

  @Test
  public void testVerifyRequestInvalidChildAttributes() throws IOException
  {
    VerifyRequestType verifyRequest = buildInvalidChildAttributesVerifyRequest(VALID_CERT_PATH);
    SignedObject signedObject = buildSignedObject(verifyRequest);

    ValidationReport report = reportBuilderService.generate(verifyRequest, signedObject, policy, null, DSSResponseType.JSON);

    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError", report.getResult().getResultMajor());
    Assert.assertEquals("urn:oasis:names:tc:dss:1.0:resultminor:GeneralError", report.getResult().getResultMinor());
  }

  /**
   * Builds a VerifyRequestType object around a provided X.509 certificate
   * @param certPath the path to the X.509 certificate to include in the request
   * @return a VerifyRequest tailored to the OASIS DSS X.509 profile, embedding the provided certificate
   * @throws IOException
   */
  private VerifyRequestType buildVerifyRequest(final String certPath) throws IOException
  {
    final Base64DataType base64Data = new Base64DataType();
    final File certFile = new File(this.getClass().getClassLoader().getResource(certPath).getFile());
    byte[] certBytes = Files.readAllBytes(certFile.toPath());
    final String base64Certificate = new String(Base64.encode(certBytes));
    base64Data.setValue(base64Certificate.getBytes());
    base64Data.setMimeType("application/pkix-cert");
    final SignatureObjectType signatureObject = new SignatureObjectType();
    signatureObject.setBase64Signature(base64Data);
    final VerifyRequestType verifyRequest = new VerifyRequestType();
    verifyRequest.setRequestID(UUID.randomUUID().toString());
    verifyRequest.setSignatureObject(signatureObject);
    verifyRequest.getProfile().add("http://docs.oasis-open.org/dss/ns/X.509");

    return verifyRequest;
  }

  private VerifyRequestType buildInvalidMimeTypeVerifyRequest(final String certPath) throws IOException
  {
    final Base64DataType base64Data = new Base64DataType();
    final File certFile = new File(this.getClass().getClassLoader().getResource(certPath).getFile());
    byte[] certBytes = Files.readAllBytes(certFile.toPath());
    final String base64Certificate = new String(Base64.encode(certBytes));
    base64Data.setValue(base64Certificate.getBytes());
    base64Data.setMimeType("application/pkix-certinvalid");
    final SignatureObjectType signatureObject = new SignatureObjectType();
    signatureObject.setBase64Signature(base64Data);
    final VerifyRequestType verifyRequest = new VerifyRequestType();
    verifyRequest.setRequestID(UUID.randomUUID().toString());
    verifyRequest.setSignatureObject(signatureObject);
    verifyRequest.getProfile().add("http://docs.oasis-open.org/dss/ns/X.509");

    return verifyRequest;
  }

  private VerifyRequestType buildInvalidChildAttributesVerifyRequest(final String certPath) throws IOException
  {
    final Base64DataType base64Data = new Base64DataType();
    final File certFile = new File(this.getClass().getClassLoader().getResource(certPath).getFile());
    byte[] certBytes = Files.readAllBytes(certFile.toPath());
    final String base64Certificate = new String(Base64.encode(certBytes));
    base64Data.setValue(base64Certificate.getBytes());
    base64Data.setMimeType("application/pkix-certinvalid");
    final SignatureObjectType signatureObject = new SignatureObjectType();
    signatureObject.setBase64Signature(base64Data);
    final VerifyRequestType verifyRequest = new VerifyRequestType();
    verifyRequest.setRequestID(UUID.randomUUID().toString());
    verifyRequest.setSignatureObject(signatureObject);
    Base64DataType base64DataType = new Base64DataType();
    base64DataType.setValue(Base64.decode("VGhpcyBmaWxlIGJlbG9uZ3MgdG8gWDUwOSB0ZXN0aW5nLgpHZW5lcmF0ZWQgYnkgVFVCSVRBSwpGaXJzdCBmaWxlIHRvIGJlIGdlbmVyYXRlZC4="));
    DocumentType document = new DocumentType();
    document.setID("1234");
    document.setRefURI("Test file.txt");
    document.setBase64Data(base64DataType);

    InputDocumentsType inputDocuments = new InputDocumentsType();
    inputDocuments.getDocument().add(document);
    verifyRequest.setInputDocuments(inputDocuments);
    verifyRequest.getProfile().add("http://docs.oasis-open.org/dss/ns/X.509");

    return verifyRequest;
  }



  /**
   * Builds a SignedObject based on a provided VerifyRequestType
   * @param verifyRequest
   * @return
   */
  private SignedObject buildSignedObject(final VerifyRequestType verifyRequest) {

    return new SignedObject(Base64.decode(verifyRequest.getSignatureObject().getBase64Signature().getValue()), SignedObjectFormat.X509, SignedObjectType.CERTIFICATE);
  }

  private SignedObject buildInvalidMimeTypeSignedObject(final VerifyRequestType verifyRequest)
  {
    return new SignedObject(Base64.decode(verifyRequest.getSignatureObject().getBase64Signature().getValue()), SignedObjectFormat.X509, SignedObjectType.CERTIFICATE);
  }
}
