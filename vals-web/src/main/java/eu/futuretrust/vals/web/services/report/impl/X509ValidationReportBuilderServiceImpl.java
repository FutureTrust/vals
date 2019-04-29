package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.SimpleCertificateReport;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.OptionalOutputsVerifyType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ResultType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.VerificationTimeInfoType;
import eu.futuretrust.vals.jaxb.oasis.saml.v2.NameIDType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import eu.futuretrust.vals.web.services.report.ValidationReportBuilderService;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.BooleanUtils;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Service
public class X509ValidationReportBuilderServiceImpl implements ValidationReportBuilderService {

  private CertificateVerifierService certificateVerifierService;

  @Autowired
  public X509ValidationReportBuilderServiceImpl(@Qualifier("httpCertificateVerifierService") final CertificateVerifierService certificateVerifierService) {
    this.certificateVerifierService = certificateVerifierService;
  }

  @Override
  public ValidationReport generate(VerifyRequestType verifyRequest,
                                   SignedObject signedObject,
                                   Policy policy,
                                   List<InputDocument> inputDocuments,
                                   DSSResponseType responseType)
  {
    final ResultType resultType = new ResultType();
    final OptionalOutputsVerifyType optionalOutputs = new OptionalOutputsVerifyType();

    if (!isVerifyRequestValid(verifyRequest)){

      resultType.setResultMajor(ResultMajor.REQUESTER_ERROR.getURI());
      resultType.setResultMinor(ResultMinor.GENERAL_ERROR.getURI());
      return new ValidationReport(resultType);
    }

    try
    {
      X509Certificate certificate = getCertificate(verifyRequest, signedObject);
      Date useVerificationTime = getUseVerificationTime(verifyRequest);
      CertificateToken token = new CertificateToken(certificate);

      CertificateValidator validator = CertificateValidator.fromCertificate(token);
      validator.setCertificateVerifier(certificateVerifierService.getCertificateVerifier());

      certificateVerifierService.getCertificateVerifier().setDataLoader(new NativeHTTPDataLoader());
      Date verificationTime = useVerificationTime != null? useVerificationTime : new Date();
      validator.setValidationTime(verificationTime);
      CertificateReports reports = validator.validate();

      resultType.setResultMajor(ResultMajor.SUCCESS.getURI());
      resultType.setResultMinor(getResultMinor(token, reports, verificationTime).getURI());

      final NameIDType certIssuerName = getSignerIdentity(verifyRequest, certificate);
      if (certIssuerName != null) {
        optionalOutputs.setSignerIdentity(certIssuerName);
      }

      final VerificationTimeInfoType verificationTimeInfo = getVerificationTimeInfo(verifyRequest, verificationTime);
      if (verificationTimeInfo != null)
      {
        optionalOutputs.setVerificationTimeInfo(verificationTimeInfo);
      }

    } catch (CertificateException e)
    {
      resultType.setResultMajor(ResultMajor.REQUESTER_ERROR.getURI());
    }

    final ValidationReport validationReport = new ValidationReport(resultType);
    validationReport.setOptionalOutputs(optionalOutputs);
    return validationReport;
  }

  private boolean isVerifyRequestValid(final VerifyRequestType verifyRequestType) {

    //InputDocument element MUT NOT be used
    if (verifyRequestType.getInputDocuments() != null &&
        (CollectionUtils.isNotEmpty(verifyRequestType.getInputDocuments().getDocument()) ||
            CollectionUtils.isNotEmpty(verifyRequestType.getInputDocuments().getTransformedData()))) {

      return false;
    }

    //Elements of OptionalInputsBase MUST NOT be used with this profile
    if (verifyRequestType.getOptionalInputs() != null
      && (verifyRequestType.getOptionalInputs().getServicePolicy() != null
            && verifyRequestType.getOptionalInputs().getServicePolicy().size() > 0
            || verifyRequestType.getOptionalInputs().getClaimedIdentity() != null
            || verifyRequestType.getOptionalInputs().getLanguage() != null
            || verifyRequestType.getOptionalInputs().getSchemas() != null
            || verifyRequestType.getOptionalInputs().getAddTimestamp() != null
            || verifyRequestType.getOptionalInputs().getOther() != null)
            && verifyRequestType.getOptionalInputs().getOther().size() > 0) {

      return false;
    }

    if (! Arrays.asList(SignedObjectFormat.X509.getMimeTypes())
            .contains(verifyRequestType.getSignatureObject().getBase64Signature().getMimeType())) {
      return false;
    }

    return true;
  }

  private X509Certificate getCertificate(final VerifyRequestType verifyRequest,
                                         final SignedObject signedObject) throws CertificateException
  {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");

    if (signedObject != null)
    {
      return (X509Certificate) factory.generateCertificate(
              new ByteArrayInputStream(signedObject.getContent()));
    } else if (verifyRequest.getOptionalInputs() != null
            && verifyRequest.getOptionalInputs().getAdditionalKeyInfo() != null)
    {
      return (X509Certificate) factory.generateCertificate(
              new ByteArrayInputStream(Base64.decode(verifyRequest.getOptionalInputs().getAdditionalKeyInfo().getX509Certificate())));
    } else throw new CertificateException("No certificate found in request");
  }

  private ResultMinor getResultMinor(final CertificateToken certificateToken,
                                     final CertificateReports reports,
                                     final Date validationTime) {

    final SimpleCertificateReport report = reports.getSimpleReport();
    String certId = report.getCertificateIds().get(0);

    if (validationTime.before(certificateToken.getNotBefore())) {
      return ResultMinor.NOT_VALID_YET;
    }

    if (isCertificateOnHold(report, certId)) {
      return ResultMinor.ON_HOLD;
    }

    if (isCertificateRevoked(certificateToken)) {
      return ResultMinor.REVOKED;
    }

    if (certificateToken.isExpiredOn(validationTime)) {
      return ResultMinor.EXPIRED;
    }

    if (isCertificateChainIncomplete(reports, certificateToken)) {
      return ResultMinor.CERTIFICATE_CHAIN_NOT_COMPLETE;
    }

    return ResultMinor.ON_ALL_DOCUMENTS;
  }

  private NameIDType getSignerIdentity(final VerifyRequestType verifyRequest, final X509Certificate certificate) {

    if (verifyRequest.getOptionalInputs() != null
            && BooleanUtils.isTrue(verifyRequest.getOptionalInputs().isReturnSignerIdentity())) {
      final String certIssuerName = certificate.getIssuerX500Principal().getName();
      final NameIDType nameIDType = new NameIDType();
      nameIDType.setValue(certIssuerName);

      return nameIDType;
    }

    return null;
  }

  private VerificationTimeInfoType getVerificationTimeInfo(final VerifyRequestType verifyRequest,
                                                           final Date verificationTime) {

    if (verifyRequest.getOptionalInputs() != null
      && verifyRequest.getOptionalInputs().isReturnVerificationTimeInfo() != null
      && verifyRequest.getOptionalInputs().isReturnVerificationTimeInfo()) {
      VerificationTimeInfoType verificationTimeInfo = new VerificationTimeInfoType();
      verificationTimeInfo.setVerificationTime(XMLGregorianCalendarBuilder.createXMLGregorianCalendar(verificationTime));

      return verificationTimeInfo;
    }

    return null;
  }

  private Date getUseVerificationTime(final VerifyRequestType verifyRequest) {
    if (verifyRequest.getOptionalInputs() != null
        && verifyRequest.getOptionalInputs().getUseVerificationTime() != null) {
      if (BooleanUtils.isTrue(verifyRequest.getOptionalInputs().getUseVerificationTime().isCurrentTime())) {
        return null;
      } else if (verifyRequest.getOptionalInputs().getUseVerificationTime().getSpecificTime() != null) {
        return verifyRequest.getOptionalInputs().getUseVerificationTime().getSpecificTime().toGregorianCalendar().getTime();
      } else if (verifyRequest.getOptionalInputs().getUseVerificationTime().getBase64Content() != null) {
        try {
          String verificationTime = new String(Base64.decode(verifyRequest.getOptionalInputs().getUseVerificationTime().getBase64Content()));
          return new Date(Long.parseLong(verificationTime));
        } catch (Exception e) {
          return null;
        }
      }
    }
    return null;
  }

  private boolean isCertificateRevoked(final CertificateToken certificateToken) {

    if(certificateToken.isRevoked() != null && certificateToken.isRevoked()) {
      return true;
    }
    return false;
  }

  private boolean isCertificateOnHold(final SimpleCertificateReport report, final String id) {

    final String reason = report.getCertificateRevocationReason(id);
    return (reason != null && reason.equalsIgnoreCase("certificateHold"));
  }

  private boolean isCertificateChainIncomplete(final CertificateReports certificateReports,
                                                final CertificateToken certificateToken) {

    if (certificateToken.isSelfIssued()
          || certificateToken.isSelfSigned()
          || certificateReports.getSimpleReport().getJaxbModel().getChain().isEmpty())
    {
      return true;
    }
    return false;
  }
}
