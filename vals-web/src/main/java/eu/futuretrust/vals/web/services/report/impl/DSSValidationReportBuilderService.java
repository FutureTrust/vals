package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.*;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.core.manifest.ManifestVerifier;
import eu.futuretrust.vals.core.manifest.exceptions.ManifestException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.AppliedSignatureValidationPolicyType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.OptionalOutputsVerifyType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureValidationReportType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectList;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ManifestResultType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ResultType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.VerificationTimeInfoType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.VerifyManifestResultsType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.*;
import eu.futuretrust.vals.jaxb.oasis.saml.v2.NameIDType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.constants.OasisX509SubjectName;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.enums.ManifestStatus;
import eu.futuretrust.vals.protocol.exceptions.*;
import eu.futuretrust.vals.protocol.helpers.VerifyRequestElementsFinder;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.input.documents.InputDocumentHash;
import eu.futuretrust.vals.protocol.output.*;
import eu.futuretrust.vals.protocol.utils.VerifyRequestUtils;
import eu.futuretrust.vals.protocol.utils.VerifyResponseUtils;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import eu.futuretrust.vals.protocol.validation.DSSEnumsParser;
import eu.futuretrust.vals.protocol.validation.DSSRevocationWrapperParser;
import eu.futuretrust.vals.protocol.validation.SignatureValidation;
import eu.futuretrust.vals.protocol.validation.validity.DSSCRLValidityParser;
import eu.futuretrust.vals.protocol.validation.validity.DSSCertificateValidityParser;
import eu.futuretrust.vals.protocol.validation.validity.DSSOCSPValidityParser;
import eu.futuretrust.vals.protocol.validation.validity.DSSTimestampValidityParser;
import eu.futuretrust.vals.web.services.report.IndividualReportBuilderService;
import eu.futuretrust.vals.web.services.report.SignatureValidationReportBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationReportBuilderService;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class DSSValidationReportBuilderService implements ValidationReportBuilderService {

  private final static Logger LOGGER = LoggerFactory
      .getLogger(DSSValidationReportBuilderService.class);

  private final CertificateVerifierService certificateVerifierService;
  private final IndividualReportBuilderService individualReportBuilderService;
  private final SignatureValidationReportBuilderService signatureValidationReportBuilderService;

  @Autowired
  public DSSValidationReportBuilderService(
      @Qualifier("httpCertificateVerifierService") final CertificateVerifierService certificateVerifierService,
      IndividualReportBuilderService individualReportBuilderService,
      SignatureValidationReportBuilderService signatureValidationReportBuilderService) {
    this.certificateVerifierService = certificateVerifierService;
    this.individualReportBuilderService = individualReportBuilderService;
    this.signatureValidationReportBuilderService = signatureValidationReportBuilderService;
  }

  @Override
  public ValidationReport generate(final VerifyRequestType verifyRequest,
      final SignedObject signedObject, final Policy policy,
      final List<InputDocument> inputDocuments, final DSSResponseType responseType)
      throws VerifyResponseException, InputDocumentException, SignedObjectException, SignatureException, ManifestException {
    final List<InputDocumentHash> inputDocumentHashes = VerifyRequestElementsFinder
        .findInputDocumentHashes(verifyRequest);
    SignatureValidation validation = new SignatureValidation(signedObject.getContent(),
        policy.getContent(), inputDocuments, inputDocumentHashes);

    Date useVerificationTime = VerifyRequestUtils.getUseVerificationTime(verifyRequest);
    if (useVerificationTime != null) {
      validation.setVerificationTime(useVerificationTime);
    }

    Reports reports = validation.validate(certificateVerifierService.getCertificateVerifier());

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
        ValidationObjectListType validationObjectListType = null;
        if (CollectionUtils.isNotEmpty(individualReport) && individualReport.get(0).getDetails() != null) {
          for (Object object : individualReport.get(0).getDetails().getAny()) {
            if (object instanceof ValidationObjectList) {
              validationObjectListType = ((ValidationObjectList) object).getValue();
            }
          }
        }

        for (SignatureWrapper individualSignatureWrapper : reports.getDiagnosticData().getSignatures()) {
          String individualSignatureId = signatureWrapper.getId();
          MainIndication individualMainIndication = DSSEnumsParser.parseMainIndication(
              reports.getSimpleReport().getIndication(individualSignatureId));
          SubIndication individualSubIndication = DSSEnumsParser.parseSubIndication(
              reports.getSimpleReport().getSubIndication(individualSignatureId));
          if (individualMainIndication == MainIndication.TOTAL_FAILED) {
            if ((individualSubIndication == SubIndication.NOT_YET_VALID)
                || (individualSubIndication == SubIndication.SIG_CONSTRAINTS_FAILURE)
                || (individualSubIndication == SubIndication.CHAIN_CONSTRAINTS_FAILURE)
                || (individualSubIndication == SubIndication.CRYPTO_CONSTRAINTS_FAILURE)) {
              individualMainIndication = MainIndication.INDETERMINATE;
            }
          }

          SignatureValidationReportType signatureValidationReportType =
              signatureValidationReportBuilderService.generateSignatureValidationReportType(
                  verifyRequest,
                  individualSignatureWrapper,
                  signedObject,
                  policy,
                  reports,
                  reports.getDiagnosticData(),
                  reports.getSimpleReport(),
                  validationObjectListType,
                  individualMainIndication,
                  individualSubIndication
              );
            optionalOutputs.getSignatureValidationReport().add(signatureValidationReportType);
        }

        optionalOutputs.getIndividualReport().addAll(individualReport);

        if (ResultMajor.SUCCESS.getURI().equals(validationReport.getResult().getResultMajor())) {
          // Result when signature validates successfully
          if (mainIndication == MainIndication.TOTAL_PASSED && subIndication == null) {
            result.setResultMinor(ResultMinor.ON_ALL_DOCUMENTS.getURI());
          }
          // Result when detached signature without document/document-hash
          if (mainIndication == MainIndication.INDETERMINATE && subIndication == SubIndication.SIGNED_DATA_NOT_FOUND) {
              result.setResultMajor(ResultMajor.REQUESTER_ERROR.getURI());
              result.setResultMinor(ResultMinor.INCORRECT_SIGNATURE.getURI());
            result.setResultMessage(VerifyResponseUtils.getResultMessage("Detached signature without input document/document-hash"));
          }
          if (mainIndication == MainIndication.INDETERMINATE && subIndication == SubIndication.NO_CERTIFICATE_CHAIN_FOUND) {
            result.setResultMajor(ResultMajor.INSUFFICIENT_INFORMATION.getURI());
            result.setResultMinor(ResultMinor.CERTIFICATE_CHAIN_NOT_COMPLETE.getURI());
          }
          // Result when detached signature with not matching document/document-hash
          if (mainIndication == MainIndication.TOTAL_FAILED && subIndication == SubIndication.HASH_FAILURE) {
            result.setResultMajor(ResultMajor.REQUESTER_ERROR.getURI());
            result.setResultMinor(ResultMinor.NOT_SUPPORTED.getURI());
            result.setResultMessage(VerifyResponseUtils.getResultMessage("Detached signature with not-matching input document/document-hash"));
          }
          if (mainIndication == MainIndication.INDETERMINATE && subIndication == SubIndication.TRY_LATER) {
            result.setResultMajor(ResultMajor.INSUFFICIENT_INFORMATION.getURI());
            result.setResultMinor(ResultMinor.CRL_NOT_AVAILABLE.getURI());
          }
          // Result when enveloping signature with input document/document-hash
          if (SignedObjectType.ENVELOPING.equals(signedObject.getType()) &&
              (CollectionUtils.isNotEmpty(inputDocuments) || CollectionUtils.isNotEmpty(inputDocumentHashes))) {
            result.setResultMajor(ResultMajor.REQUESTER_ERROR.getURI());
            result.setResultMinor(ResultMinor.GENERAL_ERROR.getURI());
            result.setResultMessage(VerifyResponseUtils.getResultMessage("Enveloping signature with input document/document-hash"));
          }
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

    for (TimestampWrapper timestampWrapper : diagnosticData
        .getTimestampList(signatureWrapper.getId()))
    {
      DSSTimestampValidityParser dssTimestampValidityParser = new DSSTimestampValidityParser(
              diagnosticData, timestampWrapper);
      TimeStampValidityType timeStampValidityType = dssTimestampValidityParser
              .getTimestampValidity();

      List<DigestAlgoAndValue> referencedObjectsByHash = new ArrayList<>();
      timestamps.add(new Timestamp(timestampWrapper.getBinaries(), timeStampValidityType, new ArrayList<>(), referencedObjectsByHash,
      timestampWrapper.getProductionTime()));
    }

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
