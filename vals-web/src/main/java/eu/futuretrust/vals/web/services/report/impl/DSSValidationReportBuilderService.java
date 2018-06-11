package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.core.manifest.ManifestVerifier;
import eu.futuretrust.vals.core.manifest.exceptions.ManifestException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.AppliedSignatureValidationPolicyType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.OptionalOutputsVerifyType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ManifestResultType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ResultType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.VerificationTimeInfoType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.VerifyManifestResultsType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CRLValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.IndividualReportType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.OCSPValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.TimeStampValidityType;
import eu.futuretrust.vals.jaxb.oasis.saml.v2.NameIDType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.constants.OasisX509SubjectName;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.enums.ManifestStatus;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.protocol.exceptions.IndividualReportException;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.exceptions.SignedObjectException;
import eu.futuretrust.vals.protocol.exceptions.SignerIdentityException;
import eu.futuretrust.vals.protocol.exceptions.ValidationObjectException;
import eu.futuretrust.vals.protocol.exceptions.VerifyResponseException;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.output.Certificate;
import eu.futuretrust.vals.protocol.output.Crl;
import eu.futuretrust.vals.protocol.output.DigestAlgoAndValue;
import eu.futuretrust.vals.protocol.output.Ocsp;
import eu.futuretrust.vals.protocol.output.Timestamp;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import eu.futuretrust.vals.protocol.validation.DSSEnumsParser;
import eu.futuretrust.vals.protocol.validation.DSSRevocationWrapperParser;
import eu.futuretrust.vals.protocol.validation.SignatureValidation;
import eu.futuretrust.vals.protocol.validation.validity.DSSCRLValidityParser;
import eu.futuretrust.vals.protocol.validation.validity.DSSCertificateValidityParser;
import eu.futuretrust.vals.protocol.validation.validity.DSSOCSPValidityParser;
import eu.futuretrust.vals.protocol.validation.validity.DSSTimestampValidityParser;
import eu.futuretrust.vals.web.services.report.IndividualReportBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationReportBuilderService;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.xml.datatype.XMLGregorianCalendar;
import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DSSValidationReportBuilderService implements ValidationReportBuilderService {

  private final static Logger LOGGER = LoggerFactory
      .getLogger(DSSValidationReportBuilderService.class);
  private final CertificateVerifierService certificateVerifierService;
  private final IndividualReportBuilderService individualReportBuilderService;

  @Autowired
  public DSSValidationReportBuilderService(CertificateVerifierService certificateVerifierService,
      IndividualReportBuilderService individualReportBuilderService) {
    this.certificateVerifierService = certificateVerifierService;
    this.individualReportBuilderService = individualReportBuilderService;
  }

  @Override
  public ValidationReport generate(final VerifyRequestType verifyRequest,
      final SignedObject signedObject, final Policy policy,
      final List<InputDocument> inputDocuments, final DSSResponseType responseType)
      throws VerifyResponseException, InputDocumentException, SignedObjectException, SignatureException, ManifestException {
    SignatureValidation validation = new SignatureValidation(signedObject.getContent(),
        policy.getContent(),
        inputDocuments);
    Reports reports = validation.validate(certificateVerifierService.getCertificateVerifier());

    for (SignatureWrapper signatureWrapper : reports.getDiagnosticData().getAllSignatures()) {
      List<XmlChainItem> certificateChain = signatureWrapper.getCertificateChain();
      if (certificateChain == null || certificateChain.isEmpty()) {
        LOGGER.info("Certificate chain is empty");
      } else {
        LOGGER.info("Certificate chain has " + certificateChain.size() + " certificates");
        String firstSignatureId = reports.getSimpleReport().getFirstSignatureId();
        eu.europa.esig.dss.validation.policy.rules.SubIndication subIndication = reports
            .getSimpleReport().getSubIndication(firstSignatureId);
        if (subIndication != null) {
          LOGGER.info(subIndication.toString());
        } else {
          LOGGER.info(reports.getSimpleReport().getIndication(firstSignatureId).toString());
        }
      }
    }

    //Todo: support multiple signatures - loop through signedObject Ids instead of only checking the first one
    final String signatureId = reports.getDiagnosticData().getFirstSignatureId();
    final SignatureWrapper signatureWrapper = reports.getDiagnosticData()
        .getSignatureById(signatureId);
    MainIndication mainIndication = DSSEnumsParser.parseMainIndication(reports.getSimpleReport()
        .getIndication(signatureId));
    final SubIndication subIndication = DSSEnumsParser.parseSubIndication(reports.getSimpleReport()
        .getSubIndication(signatureId));

    if (mainIndication == MainIndication.TOTAL_FAILED) {
      if ((subIndication == SubIndication.NOT_YET_VALID) ||
          (subIndication == SubIndication.SIG_CONSTRAINTS_FAILURE) ||
          (subIndication == SubIndication.CHAIN_CONSTRAINTS_FAILURE) ||
          (subIndication == SubIndication.CRYPTO_CONSTRAINTS_FAILURE)) {
        mainIndication = MainIndication.INDETERMINATE;
      }
    }

    final XMLGregorianCalendar validationTime = XMLGregorianCalendarBuilder
        .createXMLGregorianCalendar(
            reports.getSimpleReport().getValidationTime());

    ResultType result = getResult();
    ValidationReport validationReport = new ValidationReport(result);
    boolean signValidationReport = false;

    if (verifyRequest.getOptionalInputs() != null) {
      // TODO: as DocumentWithSignature is an Optional Input, see if it shall be excluded when there is only the DocumentWithSignature
      OptionalOutputsVerifyType optionalOutputs = ObjectFactoryUtils.FACTORY_ETSI_119_442
          .createOptionalOutputsVerifyType();

      if (containsSignVerificationReport(verifyRequest)) {
        signValidationReport = true;
      }

      List<byte[]> base64InputDocs = inputDocuments.stream()
          .map(doc -> Base64.encode(doc.getContent()))
          .collect(Collectors.toList());

      if (containsReturnVerificationReport(verifyRequest)) {

        List<IndividualReportType> individualReport = individualReportBuilderService.generate(
            signatureWrapper,
            validationTime,
            signedObject,
            reports.getSimpleReport(),
            reports.getDiagnosticData(),
            base64InputDocs,
            policy,
            getCertificates(reports.getDiagnosticData()),
            getTimestamps(reports.getDiagnosticData(), signatureWrapper),
            getOcsp(reports.getDiagnosticData()),
            getCrl(reports.getDiagnosticData()),
            mainIndication,
            subIndication
        );

        optionalOutputs.getIndividualReport().addAll(individualReport);
        if (ResultMajor.SUCCESS.getURI().equals(validationReport.getResult().getResultMajor())) {
          validationReport.getResult().setResultMinor(null);
        }
      }

      if (containsUseSignatureValidationPolicy(verifyRequest)) {
        AppliedSignatureValidationPolicyType appliedPolicy = getAppliedSignatureValidationPolicy(
            policy);
        optionalOutputs.setAppliedSignatureValidationPolicy(appliedPolicy);
      }

      if (containsVerificationTimeInfo(verifyRequest)) {
        VerificationTimeInfoType verificationTimeInfo = getVerificationTimeInfo(validationTime);
        optionalOutputs.setVerificationTimeInfo(verificationTimeInfo);
      }

      if (containsReturnSignerIdentity(verifyRequest)) {
        NameIDType signerIdentity = getSignerIdentity(signatureWrapper,
            reports.getDiagnosticData());
        optionalOutputs.setSignerIdentity(signerIdentity);
      }

      if (containsVerifyManifests(verifyRequest) && ResultMajor.SUCCESS.getURI()
          .equals(result.getResultMajor())) {
        VerifyManifestResultsType manifestResults = getVerifyManifestResults(signedObject,
            inputDocuments);
        optionalOutputs.setVerifyManifestResults(manifestResults);
        result.setResultMinor(ResultMinor.HAS_MANIFEST_RESULTS.getURI());
      }

      validationReport.setOptionalOutputs(optionalOutputs);
    }

    return validationReport;

  }

  private AppliedSignatureValidationPolicyType getAppliedSignatureValidationPolicy(Policy policy) {
    AppliedSignatureValidationPolicyType appliedSignatureValidationPolicyType = ObjectFactoryUtils.FACTORY_ETSI_119_442
        .createAppliedSignatureValidationPolicyType();
    appliedSignatureValidationPolicyType.setSignatureValidationPolicyID(policy.getUrl());
    return appliedSignatureValidationPolicyType;
  }

  private VerifyManifestResultsType getVerifyManifestResults(final SignedObject signedObject,
      final List<InputDocument> inputDocuments) throws SignatureException, ManifestException {
    ManifestVerifier verifier = new ManifestVerifier(signedObject.getContent(),
        inputDocuments.stream().map(InputDocument::getContent).collect(Collectors.toList()));
    Map<String, Boolean> references = verifier.verifyReferences();

    VerifyManifestResultsType manifestResults = ObjectFactoryUtils.FACTORY_OASIS_CORE_2
        .createVerifyManifestResultsType();

    for (Map.Entry<String, Boolean> entry : references.entrySet()) {
      ManifestResultType manifestResult = ObjectFactoryUtils.FACTORY_OASIS_CORE_2
          .createManifestResultType();
      manifestResult.setReferenceXpath(entry.getKey());
      manifestResult.setStatus(
          entry.getValue() ? ManifestStatus.VALID.getURI() : ManifestStatus.INVALID.getURI());
      // Should we add NameSpaces: manifestResult.getNsPrefixMapping();
      manifestResults.getManifestResult().add(manifestResult);
    }

    return manifestResults;
  }

  private NameIDType getSignerIdentity(final SignatureWrapper signatureWrapper,
      final DiagnosticData diagnosticData) throws SignerIdentityException {
    if (!signatureWrapper.getSigningCertificateId().equals("")) {
      final CertificateWrapper certificateWrapper = diagnosticData
          .getUsedCertificateById(signatureWrapper.getSigningCertificateId());
      final NameIDType nameIDType = ObjectFactoryUtils.FACTORY_SSTC_2.createNameIDType();
      nameIDType.setFormat(OasisX509SubjectName.URN);

      try {
        final String value = (new DSSCertificateWrapperParser())
            .getXmlCertificateField(certificateWrapper)
            .getSubjectDistinguishedName().get(1).getValue();
        nameIDType.setValue(value);
        return nameIDType;
      } catch (DSSParserException e) {
      }
    }

    throw new SignerIdentityException("Could not return SignerIdentity",
        ResultMajor.REQUESTER_ERROR, ResultMinor.INAPPROPRIATE_SIGNATURE);
  }

  private boolean containsVerifyManifests(VerifyRequestType verifyRequest) {
    return verifyRequest != null && verifyRequest.getOptionalInputs() != null &&
        verifyRequest.getOptionalInputs().isVerifyManifests() != null
        && (verifyRequest.getOptionalInputs().isVerifyManifests().equals(Boolean.TRUE));
  }

  private boolean containsReturnSignerIdentity(VerifyRequestType verifyRequest) {
    return verifyRequest != null && verifyRequest.getOptionalInputs() != null &&
        verifyRequest.getOptionalInputs().isReturnSignerIdentity() != null
        && (verifyRequest.getOptionalInputs().isReturnSignerIdentity().equals(Boolean.TRUE));
  }

  private boolean containsVerificationTimeInfo(VerifyRequestType verifyRequest) {
    return verifyRequest != null && verifyRequest.getOptionalInputs() != null &&
        verifyRequest.getOptionalInputs().isReturnVerificationTimeInfo() != null
        && (verifyRequest.getOptionalInputs().isReturnVerificationTimeInfo().equals(Boolean.TRUE));
  }

  private boolean containsUseSignatureValidationPolicy(VerifyRequestType verifyRequest) {
    return verifyRequest != null && verifyRequest.getOptionalInputs() != null &&
        verifyRequest.getOptionalInputs().getUseSignatureValidationPolicy() != null
        && CollectionUtils.isNotEmpty(
        verifyRequest.getOptionalInputs().getUseSignatureValidationPolicy()
            .getSignaturePolicyLocation());
  }

  private boolean containsReturnVerificationReport(VerifyRequestType verifyRequest) {
    return verifyRequest != null && verifyRequest.getOptionalInputs() != null &&
        verifyRequest.getOptionalInputs().getReturnVerificationReport() != null;
  }

  private boolean containsSignVerificationReport(VerifyRequestType verifyRequest) {
    return verifyRequest != null && verifyRequest.getOptionalInputs() != null &&
        verifyRequest.getOptionalInputs().isSignVerificationReport() != null
        && (verifyRequest.getOptionalInputs().isSignVerificationReport().equals(Boolean.TRUE));
  }

  private ResultType getResult() {

    ResultType result = ObjectFactoryUtils.FACTORY_OASIS_CORE_2.createResultType();
    result.setResultMajor(ResultMajor.SUCCESS.getURI());
    return result;
  }

  protected VerificationTimeInfoType getVerificationTimeInfo(XMLGregorianCalendar validationTime) {
    VerificationTimeInfoType verificationTimeInfoType = ObjectFactoryUtils.FACTORY_OASIS_CORE_2
        .createVerificationTimeInfoType();
    verificationTimeInfoType.setVerificationTime(validationTime);
    return verificationTimeInfoType;
  }

  private List<byte[]> getSignersDocuments(final SignedObject signedObject,
      final List<InputDocument> inputDocuments) throws IndividualReportException {
    switch (signedObject.getType()) {
      case ENVELOPED:
      case ENVELOPING:
        return Collections.singletonList(Base64.encode(signedObject.getContent()));
      case DETACHED:
        try {
          return inputDocumentsToSignersDocuments(inputDocuments);
        } catch (final InputDocumentException e) {
          String errorMessage = "An error occurred when performing a validation regarding the InputDocuments passed to the validation";
          throw new IndividualReportException(errorMessage, ResultMajor.RESPONDER_ERROR,
              ResultMinor.GENERAL_ERROR);
        }
      case ENVELOPING_DETACHED:
      case ENVELOPED_DETACHED:
      case ENVELOPED_ENVELOPING_DETACHED:
        final List<byte[]> signersDocuments;
        try {
          signersDocuments = inputDocumentsToSignersDocuments(inputDocuments);
        } catch (InputDocumentException e) {
          String errorMessage = "An error occurred when performing a validation regarding the Signature passed to the validation";
          throw new IndividualReportException(errorMessage, ResultMajor.RESPONDER_ERROR,
              ResultMinor.GENERAL_ERROR);
        }
        signersDocuments.add(Base64.encode(signedObject.getContent()));
        return signersDocuments;
      default:
        String errorMessage = "Unable to find the signer's document";
        throw new IndividualReportException(errorMessage, ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
    }
  }

  private List<byte[]> inputDocumentsToSignersDocuments(final List<InputDocument> inputDocuments)
      throws InputDocumentException {

    if (inputDocuments.isEmpty()) {
      throw new InputDocumentException("Missing input documents", ResultMajor.REQUESTER_ERROR,
          ResultMinor.REFERENCED_DOCUMENT_NOT_PRESENT);
    }

    return inputDocuments.stream()
        .map(doc -> Base64.encode(doc.getContent()))
        .collect(Collectors.toList());
  }

  /**
   * Get certificates used in the validation process.
   *
   * @return list of certificates
   */
  private List<Certificate> getCertificates(final DiagnosticData diagnosticData)
      throws ValidationObjectException {
    List<Certificate> certificates = new ArrayList<>();
    for (CertificateWrapper cert : diagnosticData.getUsedCertificates()) {
      try {
        DSSCertificateWrapperParser dssCertificateWrapperParser = new DSSCertificateWrapperParser();
        DSSCertificateValidityParser dssCertificateValidityParser = new DSSCertificateValidityParser(
            cert, diagnosticData.getFirstSignatureDate());
        CertificateValidityType certificateValidityType = dssCertificateValidityParser
            .getCertificateValidity();
        byte[] base64Cert = dssCertificateWrapperParser.getCertificateBase64(cert);

        certificates
            .add(new Certificate(base64Cert, certificateValidityType, cert.getRevocationData()));
      } catch (DSSParserException e) {
        String errorMessage = "Error while retrieving Certificates: " + e.getMessage();
        throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
    }
    if (certificates.isEmpty()) {
      String errorMessage = "No certificates found";
      throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    return certificates;
  }

  /**
   * Get timestamps used in the validation process.
   *
   * @return list of timestamps
   */
  private List<Timestamp> getTimestamps(final DiagnosticData diagnosticData,
      final SignatureWrapper signatureWrapper) {

    List<Timestamp> timestamps = new ArrayList<>();

    /*
    for (TimestampWrapper timestampWrapper : diagnosticData
        .getTimestampList(signatureWrapper.getId())) {
      DSSTimestampValidityParser dssTimestampValidityParser = new DSSTimestampValidityParser(
          diagnosticData, timestampWrapper);
      TimeStampValidityType timeStampValidityType = dssTimestampValidityParser
          .getTimestampValidity();

      List<DigestAlgoAndValue> referencedObjectsByHash = new ArrayList<>();
      // TODO: find base64 value, List<byte[]> referencedObjectsByBase64 = ;

      for (XmlTimestampedObject xmlTimestampedObject : timestampWrapper.getTimestampedObjects()) {
        DigestAlgoAndValue myDigestAlgoAndValue = new DigestAlgoAndValue();
        myDigestAlgoAndValue
            .setDigestAlgo(xmlTimestampedObject.getDigestAlgoAndValue().getDigestMethod());
        myDigestAlgoAndValue
            .setValue(Base64.decode(xmlTimestampedObject.getDigestAlgoAndValue().getDigestValue()));
        referencedObjectsByHash.add(myDigestAlgoAndValue);
      }

      // TODO: find base64 value, timestampWrapper.getBase64Encoded()
      timestamps.add(
          new Timestamp(null, timeStampValidityType,
              new ArrayList<>(), referencedObjectsByHash,
              timestampWrapper.getProductionTime()));
    }
    */

    return timestamps;
  }

  private List<Ocsp> getOcsp(final DiagnosticData diagnosticData) {
    List<Ocsp> ocsp = new ArrayList<>();
    Iterator<RevocationWrapper> revocationDataIterator = diagnosticData.getAllRevocationData()
        .iterator();

    for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
      if (revocationWrapper.getSource().equals("OCSPToken")) {
        try {
          DSSOCSPValidityParser dssocspValidityParser = new DSSOCSPValidityParser(diagnosticData,
              revocationWrapper);
          OCSPValidityType ocspValidityType = dssocspValidityParser.getOCSPValidity();
          DSSRevocationWrapperParser dssRevocationWrapperParser = new DSSRevocationWrapperParser();
          ocsp.add(new Ocsp(dssRevocationWrapperParser.getRevocationBase64(revocationWrapper),
              ocspValidityType));
        } catch (DSSParserException e) {
        }
      }
    }
    return ocsp;
  }

  private List<Crl> getCrl(final DiagnosticData diagnosticData) {
    List<Crl> crlList = new ArrayList<>();

    for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
      if (revocationWrapper.getSource().equals("CRLToken")) {
        DSSCRLValidityParser dsscrlValidityParser = new DSSCRLValidityParser(diagnosticData,
            revocationWrapper);
        try {
          CRLValidityType crlValidityType = dsscrlValidityParser.getCRLValidity();
          DSSRevocationWrapperParser dssRevocationWrapperParser = new DSSRevocationWrapperParser();
          crlList.add(new Crl(dssRevocationWrapperParser.getRevocationBase64(revocationWrapper),
              crlValidityType));
        } catch (DSSParserException e) {
        }
      }
    }
    return crlList;
  }
}
