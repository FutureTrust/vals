package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.jaxb.commons.ConstraintDescriptionType;
import eu.futuretrust.vals.jaxb.commons.ConstraintDescriptionsType;
import eu.futuretrust.vals.jaxb.commons.PolicyType;
import eu.futuretrust.vals.jaxb.commons.SignatureScopeType;
import eu.futuretrust.vals.jaxb.commons.SignatureScopesType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.AdditionalValidationReportDataType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.CryptoInformationType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ReportDataType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.RevocationStatusInformationType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.VOReferenceType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationReportData;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationReportDataType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.enums.RevocationReason;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.protocol.exceptions.ValidationObjectException;
import eu.futuretrust.vals.protocol.exceptions.ValidationReportDataException;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.output.RevocationInfo;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import eu.futuretrust.vals.protocol.validation.DSSRevocationWrapperParser;
import eu.futuretrust.vals.web.services.report.ValidationObjectsBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationReportDataBuilderService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ValidationReportDataBuilderServiceImpl implements ValidationReportDataBuilderService {

  private final static Logger LOGGER = LoggerFactory
      .getLogger(ValidationReportDataBuilderServiceImpl.class);
  private ValidationObjectsBuilderService validationObjectsBuilderService;

  @Autowired
  public ValidationReportDataBuilderServiceImpl(
      ValidationObjectsBuilderService validationObjectsBuilderService) {
    this.validationObjectsBuilderService = validationObjectsBuilderService;
  }

  @Override
  public ValidationReportData generate(final SignatureWrapper signatureWrapper,
      final Policy policy,
      final DiagnosticData diagnosticData,
      final SimpleReport simpleReport,
      final MainIndication mainIndication,
      final SubIndication subIndication,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException, ValidationReportDataException {

    ValidationReportDataType validationReportDataType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationReportDataType();
    setValidationData(signatureWrapper, policy, simpleReport, mainIndication, subIndication,
        validationReportDataType, validationObjectListType, diagnosticData);

    ValidationReportData validationReportData = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationReportData(validationReportDataType);
    return validationReportData;
  }

  private void setValidationData(final SignatureWrapper signatureWrapper,
      final Policy policy,
      final SimpleReport simpleReport,
      final MainIndication mainIndication,
      final SubIndication subIndication,
      ValidationReportDataType validationReportDataType,
      final ValidationObjectListType validationObjectListType,
      final DiagnosticData diagnosticData)
      throws ValidationReportDataException, ValidationObjectException {
    switch (mainIndication) {
      case TOTAL_PASSED:
        setAVRDForTotalPassed(signatureWrapper, diagnosticData, validationReportDataType,
            validationObjectListType);
        return;
      case TOTAL_FAILED:
        setAVRDForTotalFailed(signatureWrapper, diagnosticData, subIndication, simpleReport,
            validationReportDataType, validationObjectListType);
        return;
      case INDETERMINATE:
        setAVRDForIndeterminate(signatureWrapper, policy, diagnosticData, simpleReport,
            subIndication, validationReportDataType, validationObjectListType);
        return;
      default:
        break;
    }
  }

  /**
   * Add the Signing Certificate into the Associated Validation Report Data
   *
   * @param x509base64 base64 representation of the certificate
   * @throws ValidationObjectException Whenever the certificate represented by {@code x509base64}
   * cannot be retrieved from the Validation Objects
   */
  public void setSigningCertificate(byte[] x509base64,
      final ValidationReportDataType validationReportData,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException {
    VOReferenceType voReference = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createVOReferenceType();

    Optional<ValidationObjectType> optionalValidationObjectType = validationObjectsBuilderService
        .findByBase64(x509base64, ValidationObjectTypeId.CERTIFICATE, validationObjectListType);

    if (!optionalValidationObjectType.isPresent()) {
      String errorMessage = "Signing Certificate is missing in the Validation Objects";
      throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    voReference.getVOReference().add(optionalValidationObjectType.get());
    validationReportData.setSigningCertificate(voReference);
  }

  /**
   * Add the Certificate Chain into the Associated Validation Report Data
   *
   * @param x509Base64List base64 representation of the certificate chain
   */
  public void setCertificateChain(final List<byte[]> x509Base64List,
      final ValidationReportDataType validationReportData,
      final ValidationObjectListType validationObjectListType) throws ValidationObjectException {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Setting certificate chain...");
    }
    VOReferenceType voReference = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createVOReferenceType();
    for (byte[] x509Base64 : x509Base64List) {
      Optional<ValidationObjectType> optionalValidationObjectType = validationObjectsBuilderService
          .findByBase64(x509Base64, ValidationObjectTypeId.CERTIFICATE, validationObjectListType);
      if (!optionalValidationObjectType.isPresent()) {
        String errorMessage = "Certificate is missing in the Validation Objects";
        throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
      voReference.getVOReference().add(optionalValidationObjectType.get());
    }
    if (LOGGER.isInfoEnabled()) {
      if (voReference.getVOReference() != null) {
        LOGGER.info("... with " +
            (voReference.getVOReference() != null ? voReference.getVOReference().size() : "0") +
            " certificates");
      }
    }
    validationReportData.setCertificateChain(voReference);
  }

  /**
   * Add the Signed Data Objects into the Associated Validation Report Data
   *
   * @param base64List base64 representation of the certificate chain
   */
  public void setSignedDataObjects(final List<byte[]> base64List,
      final ValidationReportDataType validationReportData,
      final ValidationObjectListType validationObjectListType) throws ValidationObjectException {
    VOReferenceType voReference = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createVOReferenceType();
    for (byte[] base64 : base64List) {
      Optional<ValidationObjectType> vo = validationObjectsBuilderService
          .findByBase64(base64, validationObjectListType);
      if (!vo.isPresent()) {
        String errorMessage = "Signed Data Object is missing in the Validation Objects";
        throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
      voReference.getVOReference().add(vo.get());
    }
    validationReportData.setSignedDataObjects(voReference);
  }


  /**
   * Add a Revocation Status Information Element in the Associated Validation Report Data
   *
   * @param x509CertificateBase64 base64 representation of the certificate which is revoked
   * @param revocationTime moment of revocation
   * @param revocationReason reason of revocation
   * @param revocationDataBase64 revocation data encoded in base 64
   * @param voType either CRL or OCSP response
   */
  public void setRevocationStatusInformationElement(final byte[] x509CertificateBase64,
      final Date revocationTime,
      final RevocationReason revocationReason,
      final byte[] revocationDataBase64,
      final ValidationObjectTypeId voType,
      final ValidationObjectListType validationObjectListType,
      final ValidationReportDataType validationReportDataType)
      throws ValidationObjectException, ValidationReportDataException {

    if (voType != ValidationObjectTypeId.OCSPRESPONSE && voType != ValidationObjectTypeId.CRL) {
      throw new ValidationReportDataException(
          "Revocation Status Information should identify a CRL or OCSP response",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    Optional<ValidationObjectType> revocationVO = validationObjectsBuilderService
        .findByBase64(revocationDataBase64, voType, validationObjectListType);
    if (!revocationVO.isPresent()) {
      String errorMessage = "CRL or OCSP Response is missing in the Validation Objects";
      throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    setRevocationStatusInformationElement(x509CertificateBase64, revocationTime, revocationReason,
        revocationVO.get(), validationReportDataType, validationObjectListType);
  }

  /**
   * Add a Revocation Status Information Element in the Associated Validation Report Data
   *
   * @param x509CertificateBase64 base64 representation of the certificate which is revoked
   * @param revocationTime moment of revocation
   * @param revocationReason reason of revocation
   * @param revocationVO Validation Object referencing a CRL or OCSP response
   */
  private void setRevocationStatusInformationElement(final byte[] x509CertificateBase64,
      final Date revocationTime,
      final RevocationReason revocationReason,
      final ValidationObjectType revocationVO,
      final ValidationReportDataType validationReportData,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException {

    RevocationStatusInformationType revocationStatusInformationType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createRevocationStatusInformationType();

    // Adding the revoked certificate
    Optional<ValidationObjectType> optionalCertificateVO = validationObjectsBuilderService
        .findByBase64(x509CertificateBase64, ValidationObjectTypeId.CERTIFICATE,
            validationObjectListType);
    if (!optionalCertificateVO.isPresent()) {
      String errorMessage = "Certificate is missing in the Validation Objects";
      throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    // identifier referencing a certificate
    VOReferenceType voReferenceToRevokedCertificate = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createVOReferenceType();
    voReferenceToRevokedCertificate.getVOReference().add(optionalCertificateVO.get());
    revocationStatusInformationType.setValidationObjectId(voReferenceToRevokedCertificate);

    // identifier referencing a CRL or OCSP response
    VOReferenceType voReferenceToRevocationObject = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createVOReferenceType();
    voReferenceToRevocationObject.getVOReference().add(revocationVO);
    revocationStatusInformationType.setRevocationObject(voReferenceToRevocationObject);

    // time of revocation
    revocationStatusInformationType
        .setRevocationTime(XMLGregorianCalendarBuilder.createXMLGregorianCalendar(revocationTime));

    // reason for the revocation
    revocationStatusInformationType.setRevocationReason(revocationReason.getURI());

    validationReportData.setRevocationStatusInformation(revocationStatusInformationType);
  }

  /**
   * Add a Crypto Information into the Associated Validation Report Data
   *
   * @param algorithmUri URI of the cryptographic algorithm that has been used when producing the
   * object
   * @param notAfter time information up to which the algorithm or algorithm-parameters were
   * considered secure
   * @param voBase64 base64 representation of an object in the Signature Validation Objects
   * @throws ValidationObjectException Whenever the Validation Object represented by {@code
   * voBase64} cannot be retrieved from the Validation Objects
   */
  public void setCryptoInformation(final String algorithmUri,
      final Date notAfter,
      final byte[] voBase64,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException {
    Optional<ValidationObjectType> vo = validationObjectsBuilderService
        .findByBase64(voBase64, validationObjectListType);
    if (!vo.isPresent()) {
      throw new ValidationObjectException(
          "Could not find the crypto information (Base64) in Validation Object",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
    setCryptoInformation(algorithmUri, notAfter, vo.get(), validationObjectListType);
  }

  /**
   * Add a Crypto Information into the Associated Validation Report Data
   *
   * @param algorithmUri URI of the cryptographic algorithm that has been used when producing the
   * object
   * @param notAfter time information up to which the algorithm or algorithm-parameters were
   * considered secure
   * @param voUri URI of an object in the Signature Validation Objects
   * @throws ValidationObjectException Whenever the Validation Object represented by {@code voUri}
   * cannot be retrieved from the Validation Objects
   */
  public void setCryptoInformation(final String algorithmUri,
      final Date notAfter,
      final String voUri,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException {
    Optional<ValidationObjectType> vo = validationObjectsBuilderService
        .findByUri(voUri, validationObjectListType);
    if (!vo.isPresent()) {
      throw new ValidationObjectException(
          "Could not find the crypto information (URI) in Validation Object",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
    setCryptoInformation(algorithmUri, notAfter, vo.get(), validationObjectListType);
  }

  /**
   * Add a Crypto Information into the Associated Validation Report Data
   *
   * @param algorithmUri URI of the cryptographic algorithm that has been used when producing the
   * object
   * @param notAfter time information up to which the algorithm or algorithm-parameters were
   * considered secure
   * @param voObject direct object in the Signature Validation Objects
   * @throws ValidationObjectException Whenever the Validation Object represented by {@code
   * voObject} cannot be retrieved from the Validation Objects
   */
  public void setCryptoInformation(final String algorithmUri,
      final Date notAfter,
      final Object voObject,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException {
    Optional<ValidationObjectType> vo = validationObjectsBuilderService
        .findByDirect(voObject, validationObjectListType);
    if (!vo.isPresent()) {
      throw new ValidationObjectException(
          "Could not find the crypto information (Object) in Validation Object",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
    setCryptoInformation(algorithmUri, notAfter, vo.get(), validationObjectListType);
  }

  /**
   * Add a Crypto Information into the Associated Validation Report Data
   *
   * @param algorithmUri URI of the cryptographic algorithm that has been used when producing the
   * object
   * @param notAfter time information up to which the algorithm or algorithm-parameters were
   * considered secure
   * @param vo Validation Object element to be referenced
   */
  private void setCryptoInformation(String algorithmUri,
      Date notAfter,
      ValidationObjectType vo,
      final ValidationReportDataType validationReportData) {
    VOReferenceType voReference = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createVOReferenceType();
    voReference.getVOReference().add(vo);

    CryptoInformationType cryptoInformationType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createCryptoInformationType();
    cryptoInformationType.setAlgorithm(algorithmUri);
    cryptoInformationType
        .setNotAfter(XMLGregorianCalendarBuilder.createXMLGregorianCalendar(notAfter));
    cryptoInformationType.setValidationObjectId(voReference);

    validationReportData.setCryptoInformation(cryptoInformationType);
  }

  /**
   * Add the Additional Data into the Associated Validation Report DataU
   *
   * @param element actual additional data
   */
  public void setAdditionalData(final String type,
      final Object element,
      final ValidationReportDataType validationReportData) {
    ReportDataType reportData = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createReportDataType();
    reportData.setInfoType(type);
    reportData.setInfoData(element);

    AdditionalValidationReportDataType additionalData = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createAdditionalValidationReportDataType();
    additionalData.setReportData(reportData);

    validationReportData.setAdditionalValidationReportData(additionalData);
  }

  private void setAVRDForTotalPassed(final SignatureWrapper signatureWrapper,
      final DiagnosticData diagnosticData,
      final ValidationReportDataType validationReportDataType,
      final ValidationObjectListType validationObjectListType)
      throws ValidationReportDataException, ValidationObjectException {
    LOGGER.info("Setting cert chain in totalPassed");
    setCertificateChain(getCertificateChainAVRD(signatureWrapper, diagnosticData),
        validationReportDataType, validationObjectListType);
  }

  public void setAVRDForTotalFailed(final SignatureWrapper signatureWrapper,
      final DiagnosticData diagnosticData,
      final SubIndication subIndication,
      final SimpleReport simpleReport,
      ValidationReportDataType validationReportDataType,
      ValidationObjectListType validationObjectListType)
      throws ValidationReportDataException, ValidationObjectException {
    switch (subIndication) {
      case HASH_FAILURE:
        // The validation process shall provide:
        // - An identifier (s) (e.g. a URI or OID) uniquely identifying the element within the signed data object (such as the signature attributes, or the SD) that caused the failure.
        SignatureScopesType signatureScopes = getSignatureScopesAVRD(simpleReport);
        setAdditionalData(
            SignatureScopeType.class.getSimpleName(),
            signatureScopes,
            validationReportDataType);
        break;
      case SIG_CRYPTO_FAILURE:
        // The validation process shall provide the output:
        // - The signing certificate used in the validation process.
        setSigningCertificate(
            getSigningCertificateAVRD(signatureWrapper, diagnosticData),
            validationReportDataType,
            validationObjectListType);
        break;
      case REVOKED:
        // ETSI TS 119 102-2 (clause 4.2.12.5): Revocation Status Information Element shall be present when the main status indication is TOTAL_FAILED or INDETERMINATE and the status sub-indication is REVOKED resp. REVOKED_NO_POE or REVOKED_CA_NO_POE.
        // The validation process shall provide the following:
        // - The certificate chain used in the validation process.
        // - The time and, if available, the reason of revocation of the signing certificate.
        //individualReportBuilder.getValidationReportDataBuilder()
        LOGGER.info("Setting cert chain in setAVRDForTotalFailed");
        setCertificateChain(getCertificateChainAVRD(signatureWrapper, diagnosticData),
            validationReportDataType,
            validationObjectListType);
        RevocationInfo revocationInfo = getRevocationInfoAVRD(
            getSigningCertificateAVRD(signatureWrapper, diagnosticData),
            diagnosticData);
        setRevocationStatusInformationElement(
            getSigningCertificateAVRD(signatureWrapper, diagnosticData),
            revocationInfo.getRevocationTime(), revocationInfo.getRevocationReason(),
            revocationInfo.getRevocationDataBase64(), revocationInfo.getVoType(),
            validationObjectListType,
            validationReportDataType);
        break;
      default:
        break;
    }
  }

  private void setAVRDForIndeterminate(final SignatureWrapper signatureWrapper,
      final Policy policy,
      final DiagnosticData diagnosticData,
      final SimpleReport simpleReport,
      final SubIndication subIndication,
      final ValidationReportDataType validationReportDataType,
      final ValidationObjectListType validationObjectListType)
      throws ValidationReportDataException, ValidationObjectException {

    switch (subIndication) {
      case SIG_CONSTRAINTS_FAILURE:
        // The validation process shall provide:
        // - The set of constraints that have not been met by the signature.
        setAdditionalData(ConstraintDescriptionsType.class.getSimpleName(),
            getConstraintsInFailureAVRD(signatureWrapper, simpleReport), validationReportDataType);
        break;
      case CHAIN_CONSTRAINTS_FAILURE:
        // The validation process shall output:
        // - The certificate chain used in the validation process.
        // - The set of constraints that have not been met by the chain.
        LOGGER.info("Setting cert chain in setAVRDForIndeterminate (chain constraints failure)");
        setCertificateChain(getCertificateChainAVRD(signatureWrapper, diagnosticData),
            validationReportDataType, validationObjectListType);
        setAdditionalData(ConstraintDescriptionsType.class.getSimpleName(),
            getConstraintsInFailureAVRD(signatureWrapper, simpleReport), validationReportDataType);
        break;
      case CERTIFICATE_CHAIN_GENERAL_FAILURE:
        // The process shall output:
        // - Additional information regarding the reason.
        // (information can be the certificate chain itself if present)
        // (the signing certificate if present)
        try {
          LOGGER.info(
              "Setting cert chain in setAVRDForIndeterminate (certificate chain general failure)");
          setCertificateChain(getCertificateChainAVRD(signatureWrapper, diagnosticData),
              validationReportDataType, validationObjectListType);
          setSigningCertificate(getSigningCertificateAVRD(signatureWrapper, diagnosticData),
              validationReportDataType, validationObjectListType);
        } catch (ValidationObjectException e) {
          // ignore, those are not mandatory
        }

        break;
      case CRYPTO_CONSTRAINTS_FAILURE:
        // ETSI TS 119 102-2 (clause 4.2.12.6): Crypto Information Element shall be present when the main status indication is INDETERMINATE and the sub-indication is CRYPTO_CONSTRAINTS_FAILURE.
        // The process shall output:
        // - Identification of the material (signature, certificate) that is produced using an algorithm or key size below the required cryptographic security level.
        // - If known, the time up to which the algorithm or key size were considered secure
        // TODO: individualReportBuilder.setCryptoInformation(, , );
        break;
      case EXPIRED:
        // The process shall output:
        // - The validated certificate chain.
        LOGGER.info("Setting cert chain in setAVRDForIndeterminate (expired)");
        setCertificateChain(getCertificateChainAVRD(signatureWrapper, diagnosticData),
            validationReportDataType, validationObjectListType);
        break;
      case NOT_YET_VALID:
        // Nothing
        break;
      case FORMAT_FAILURE:
        // Nothing
        break;
      case POLICY_PROCESSING_ERROR:
        // The validation process shall provide:
        // - Additional information on the problem.
        // (the policy URI if present and known)
        // (the policy Base64 if present and known)
        PolicyType policyType = getPolicyAVRD(policy);
        //individualReportBuilder.getValidationReportDataBuilder()
        setAdditionalData(PolicyType.class.getSimpleName(), policyType, validationReportDataType);
        break;
      case SIGNATURE_POLICY_NOT_AVAILABLE:
        // Nothing
        break;

      case TIMESTAMP_ORDER_FAILURE:
        // The validation process shall output:
        // - The list of timestamps that do not respect the ordering constraints
        //individualReportBuilder.getValidationReportDataBuilder()
        // TODO: setSignedDataObjects(getTimestampsNotRespectingOrderingConstraints(diagnosticData),validationReportDataType, validationObjectListType);
        break;

      case NO_SIGNING_CERTIFICATE_FOUND:
        // Nothing
        break;
      case NO_CERTIFICATE_CHAIN_FOUND:
        LOGGER.info("No certificate chain found");
        break;
      case REVOKED_NO_POE:
        // ETSI TS 119 102-2 (clause 4.2.12.5): Revocation Status Information Element shall be present when the main status indication is TOTAL_FAILED or INDETERMINATE and the status sub-indication is REVOKED resp. REVOKED_NO_POE or REVOKED_CA_NO_POE.
        // The validation process shall provide the following:
        // - The certificate chain used in the validation process.
        // - The time and the reason of revocation of the signing certificate.
        LOGGER.info("Setting cert chain in setAVRDForIndeterminate (chain constraints failure)");
        setCertificateChain(getCertificateChainAVRD(signatureWrapper, diagnosticData),
            validationReportDataType, validationObjectListType);
        RevocationInfo revocationInfo = getRevocationInfoAVRD(
            getSigningCertificateAVRD(signatureWrapper, diagnosticData), diagnosticData);
        setRevocationStatusInformationElement(
            getSigningCertificateAVRD(signatureWrapper, diagnosticData),
            revocationInfo.getRevocationTime(), revocationInfo.getRevocationReason(),
            revocationInfo.getRevocationDataBase64(), revocationInfo.getVoType(),
            validationObjectListType, validationReportDataType);
        break;
      case REVOKED_CA_NO_POE:
        // ETSI TS 119 102-2 (clause 4.2.12.5): Revocation Status Information Element shall be present when the main status indication is TOTAL_FAILED or INDETERMINATE and the status sub-indication is REVOKED resp. REVOKED_NO_POE or REVOKED_CA_NO_POE.
        // The validation process shall provide the following:
        // - The certificate chain which includes the revoked CA certificate.
        // - The time and the reason of revocation of the certificate.
        LOGGER.info("Setting cert chain in setAVRDForIndeterminate (REVOKED_CA_NO_POE)");
        setCertificateChain(getCertificateChainAVRD(signatureWrapper, diagnosticData),
            validationReportDataType, validationObjectListType);
        RevocationInfo revocationInfo2 = getRevocationInfoAVRD(
            getSigningCertificateAVRD(signatureWrapper, diagnosticData), diagnosticData);
        setRevocationStatusInformationElement(
            getCACertificateAVRD(signatureWrapper, diagnosticData),
            revocationInfo2.getRevocationTime(), revocationInfo2.getRevocationReason(),
            revocationInfo2.getRevocationDataBase64(), revocationInfo2.getVoType(),
            validationObjectListType,
            validationReportDataType);
        break;
      case OUT_OF_BOUNDS_NO_POE:
        // Nothing
        break;
      case CRYPTO_CONSTRAINTS_FAILURE_NO_POE:
        // ETSI TS 119 102-2 (clause 4.2.12.6): Crypto Information Element shall be present when the main status indication is INDETERMINATE and the sub-indication is CRYPTO_CONSTRAINTS_FAILURE.
        // The process shall output:
        // - Identification of the material (signature, certificate) that is produced using an algorithm or key size below the required cryptographic security level.
        // - If known, the time up to which the algorithm or key size were considered secure
        // TODO: individualReportBuilder.setCryptoInformation(, , );
        break;
      case NO_POE:
        // The validation process shall identify:
        // - At least the signed objects for which the POEs are missing.
        // TODO: find the signed objects for which the POEs are missing.
        break;
      case TRY_LATER:
        // The validation process shall output:
        // - The point of time, where the necessary revocation information is expected to become available.
        // TODO: find the point of time where the necessary revocation information is expected to become available.
        break;
      case SIGNED_DATA_NOT_FOUND:
        // The process should output when available:
        // - The identifier (s) (e.g. an URI) of the signed data that caused the failure.
        SignatureScopesType signatureScopes = getSignatureScopesAVRD(simpleReport);
        setAdditionalData(SignatureScopeType.class.getSimpleName(), signatureScopes,
            validationReportDataType);

        break;
      case GENERIC:
        // The validation process shall output:
        // - Additional information why the validation status has been declared Indeterminate.
        // (nothing)
        break;
      default:
        break;
    }
  }

  /**
   * Get An identifier (s) (e.g. an URI or OID) uniquely identifying the element within the signed
   * data object.
   *
   * @return a list of identifiers uniquely identifying the element within the signed data object
   */
  private SignatureScopesType getSignatureScopesAVRD(final SimpleReport simpleReport) {
    if (simpleReport == null || simpleReport.getJaxbModel() == null
        || simpleReport.getJaxbModel().getSignature() == null) {
      // Unable to find signatures
      return new SignatureScopesType();
    }

    List<SignatureScopeType> signatureScopes = simpleReport.getJaxbModel().getSignature()
        .stream()
        .filter(sig -> Objects.nonNull(sig)
            && Objects.nonNull(sig.getSubIndication())
            && ((sig.getSubIndication()
            .equals(eu.europa.esig.dss.validation.policy.rules.SubIndication.HASH_FAILURE))
            || (sig.getSubIndication()
            .equals(
                eu.europa.esig.dss.validation.policy.rules.SubIndication.SIGNED_DATA_NOT_FOUND)))
            && CollectionUtils.isNotEmpty(sig.getSignatureScope()))
        .map(XmlSignature::getSignatureScope)
        .flatMap(List::stream)
        .map(scope -> {
          // if the name contains the CharSequence "Full", it means that it is the signature itself and the URI of the signature is ""
          String uri = scope.getName().contains("Full") ? "" : scope.getName();
          SignatureScopeType signatureScopeType = new SignatureScopeType();
          signatureScopeType.setURI(uri);
          return signatureScopeType;
        }).collect(Collectors.toList());

    SignatureScopesType signatureScopesType = ObjectFactoryUtils.FACTORY_COMMONS
        .createSignatureScopesType();
    signatureScopesType.getSignatureScope().addAll(signatureScopes);
    return signatureScopesType;
  }

  /**
   * Get the Signing Certificate used in the validation process.
   *
   * @return base64 representation of the signing certificate
   */
  private byte[] getSigningCertificateAVRD(final SignatureWrapper signatureWrapper,
      final DiagnosticData diagnosticData) throws ValidationReportDataException {
    if (!signatureWrapper.getSigningCertificateId().equals("")) {
      CertificateWrapper certificateWrapper = diagnosticData
          .getUsedCertificateById(signatureWrapper.getSigningCertificateId());
      byte[] certToBase64;
      try {
        certToBase64 = new DSSCertificateWrapperParser().getCertificateBase64(certificateWrapper);
      } catch (DSSParserException e) {
        String errorMessage = "Error while retrieving signing certificate: " + e.getMessage();
        throw new ValidationReportDataException(errorMessage, ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
      return certToBase64;
    } else {
      String errorMessage = "Error while retrieving signing certificate";
      throw new ValidationReportDataException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
  }

  /**
   * Returns the RevocationInfo associated to the certificate given in BASE64 {@code
   * certificateBase64}
   *
   * @param certificateBase64 a X509 certificate encoded in B64
   * @throws ValidationReportDataException in case a RevocationInfo could not be build for {@code
   * certificateBase64}
   */
  private RevocationInfo getRevocationInfoAVRD(byte[] certificateBase64,
      final DiagnosticData diagnosticData)
      throws ValidationReportDataException {
    CertificateWrapper searchedCW = null;
    try {
      for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
        byte[] currentCertB64 = (new DSSCertificateWrapperParser())
            .getCertificateBase64(certificateWrapper);
        if (Arrays.equals(currentCertB64, certificateBase64)) {
          searchedCW = certificateWrapper;
        }
      }

      if (searchedCW == null) {
        throw new ValidationReportDataException(
            "The certificate is not found in the diagnostic data available",
            ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
      }

      RevocationInfo revocationInfo = new RevocationInfo();

      RevocationWrapper latestRevocationWrapper = searchedCW.getLatestRevocationData();
      revocationInfo
          .setRevocationReason(RevocationReason.fromURI(latestRevocationWrapper.getReason()));
      revocationInfo.setRevocationTime(latestRevocationWrapper.getRevocationDate());
      revocationInfo.setRevocationDataBase64(
          (new DSSRevocationWrapperParser()).getRevocationBase64(latestRevocationWrapper));

      ValidationObjectTypeId validationObjectTypeId = null;

      if (latestRevocationWrapper.getSource().equals("OCSPToken")) {
        validationObjectTypeId = ValidationObjectTypeId.OCSPRESPONSE;
      }
      if (latestRevocationWrapper.getSource().equals("CRLToken")) {
        validationObjectTypeId = ValidationObjectTypeId.CRL;
      }
      if (validationObjectTypeId == null) {
        throw new ValidationReportDataException(
            "Revocation Status Information should identify a CRL or OCSP response",
            ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
      }

      revocationInfo.setVoType(validationObjectTypeId);
      revocationInfo.setX509CertificateBase64(certificateBase64);

      return revocationInfo;
    } catch (DSSParserException e) {
      String errorMessage = "There was an error while retrieving the Revocation informations";
      throw new ValidationReportDataException(
          errorMessage, e,
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
  }

  /**
   * Get the Certificate Chain used in the validation process.
   *
   * @return a list of base64 representation of the certificate chain
   */
  private List<byte[]> getCertificateChainAVRD(SignatureWrapper signatureWrapper,
      DiagnosticData diagnosticData) throws ValidationReportDataException {
    List<byte[]> certificateChain = new ArrayList<>();
    for (XmlChainItem xmlCertificate : signatureWrapper.getCertificateChain()) {
      try {
        CertificateWrapper certificateWrapper = diagnosticData
            .getUsedCertificateById(xmlCertificate.getId());
        certificateChain
            .add(new DSSCertificateWrapperParser().getCertificateBase64(certificateWrapper));
      } catch (DSSParserException e) {
        String errorMessage = "Unable to find certificate chain: " + e.getMessage();
        throw new ValidationReportDataException(errorMessage, ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
    }
    if (certificateChain.isEmpty()) {
      String errorMessage = "Unable to find certificate chain";
      throw new ValidationReportDataException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    return certificateChain;
  }

  private ConstraintDescriptionsType getConstraintsInFailureAVRD(
      final SignatureWrapper signatureWrapper,
      final SimpleReport simpleReport) {

    List<String> errors = simpleReport.getErrors(signatureWrapper.getId());
    ConstraintDescriptionsType constraintDescriptions = ObjectFactoryUtils.FACTORY_COMMONS
        .createConstraintDescriptionsType();

    List<ConstraintDescriptionType> listOfConstraintDescriptions = constraintDescriptions
        .getConstraintDescription();
    for (String error : errors) {
      ConstraintDescriptionType constraintDescription = ObjectFactoryUtils.FACTORY_COMMONS
          .createConstraintDescriptionType();
      constraintDescription.setDescription(error);
      listOfConstraintDescriptions.add(constraintDescription);
    }
    return constraintDescriptions;
  }

  /**
   * Get The policy URI and The Base64 representation of the policy data object.
   *
   * @return a list of identifiers uniquely identifying the element within the signed data object
   */
  private PolicyType getPolicyAVRD(final Policy policy) {
    PolicyType policyType = ObjectFactoryUtils.FACTORY_COMMONS.createPolicyType();
    if (StringUtils.isNotEmpty(policy.getUrl())) {
      policyType.setURI(policy.getUrl());
    }
    if (policy.getContent() != null) {
      policyType.setValue(Base64.encode(policy.getContent()));
    }
    return policyType;
  }

  /**
   * Returns the Base64 representation of the {@code signatureWrapper}'s last certificate in it's
   * identified certificate chain
   *
   * @param signatureWrapper a SignatureWrapper
   * @param diagnosticData a DiagnosticData
   * @throws ValidationReportDataException whenever the last certificate could not be found and
   * encoded in base 64
   */
  private byte[] getCACertificateAVRD(SignatureWrapper signatureWrapper,
      DiagnosticData diagnosticData) throws ValidationReportDataException {
    CertificateWrapper certificateWrapper = diagnosticData
        .getUsedCertificateById(signatureWrapper.getLastChainCertificateId());
    try {
      return (new DSSCertificateWrapperParser()).getCertificateBase64(certificateWrapper);
    } catch (DSSParserException e) {
      String errorMessage = "Could not find the CA's certificate in the certificate chain";
      throw new ValidationReportDataException(
          errorMessage,
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
  }

  private List<byte[]> getTimestampsNotRespectingOrderingConstraints(final DiagnosticData diagnosticData) {

    return diagnosticData.getAllTimestamps().stream()
            .map(timestampWrapper -> timestampWrapper.getBase64Encoded().getBytes())
            .collect(Collectors.toList());
  }

}
