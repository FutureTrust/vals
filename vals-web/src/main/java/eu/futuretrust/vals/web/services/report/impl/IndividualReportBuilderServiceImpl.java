package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureQuality;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureQualityType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureValidationProcess;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureValidationProcessType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignerInformationType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignersDocument;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignersDocumentType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.VOReferenceType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationConstraints;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationConstraintsType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectList;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationReportData;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.DigestAlgAndValueType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.ObjectIdentifierType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.QualifyingProperties;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignaturePolicyIdType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignaturePolicyIdentifierType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v1.AdditionalTimeInfoType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v1.InternationalStringType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v1.Result;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v1.VerificationTimeInfo;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v1.VerificationTimeInfoType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.Identifier;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.IdentifierType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.IndividualReportType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.PropertiesType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedObjectIdentifierType;
import eu.futuretrust.vals.jaxb.oasis.xmldsig.core.DigestMethodType;
import eu.futuretrust.vals.jaxb.oasis.xmldsig.core.ObjectType;
import eu.futuretrust.vals.jaxb.oasis.xmldsig.core.X509DataType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.constants.BestSignatureTimeURI;
import eu.futuretrust.vals.protocol.constants.SubjectNameInfo;
import eu.futuretrust.vals.protocol.enums.SignatureValidationProcessID;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.protocol.exceptions.IndividualReportException;
import eu.futuretrust.vals.protocol.exceptions.MessageDigestException;
import eu.futuretrust.vals.protocol.exceptions.ValidationObjectException;
import eu.futuretrust.vals.protocol.exceptions.VerifyResponseException;
import eu.futuretrust.vals.protocol.helpers.MarshallerSingleton;
import eu.futuretrust.vals.protocol.helpers.exceptions.MarshallerSingletonException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.output.Certificate;
import eu.futuretrust.vals.protocol.output.Crl;
import eu.futuretrust.vals.protocol.output.Ocsp;
import eu.futuretrust.vals.protocol.output.SignatureAttributes;
import eu.futuretrust.vals.protocol.output.SignatureQualification;
import eu.futuretrust.vals.protocol.output.SignerInformation;
import eu.futuretrust.vals.protocol.output.Timestamp;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import eu.futuretrust.vals.web.properties.CryptoProperties;
import eu.futuretrust.vals.web.services.report.IndividualReportBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationObjectsBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationReportDataBuilderService;
import eu.futuretrust.vals.web.services.report.XAdESPropertiesMapperService;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Optional;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

@Service
public class IndividualReportBuilderServiceImpl implements IndividualReportBuilderService {

  private CryptoProperties cryptoProperties;
  private ValidationObjectsBuilderService validationObjectsBuilderService;
  private ValidationReportDataBuilderService validationReportDataBuilderService;
  private XAdESPropertiesMapperService xAdESPropertiesMapperService;

  @Autowired
  public IndividualReportBuilderServiceImpl(CryptoProperties cryptoProperties,
      ValidationObjectsBuilderService validationObjectsBuilderService,
      ValidationReportDataBuilderService validationReportDataBuilderService,
      XAdESPropertiesMapperService xAdESPropertiesMapperService) {
    this.cryptoProperties = cryptoProperties;
    this.validationObjectsBuilderService = validationObjectsBuilderService;
    this.validationReportDataBuilderService = validationReportDataBuilderService;
    this.xAdESPropertiesMapperService = xAdESPropertiesMapperService;
  }

  /**
   * Return Individual Report that has been built
   *
   * @return Individual Report
   */
  @Override
  public List<IndividualReportType> generate(
      final SignatureWrapper signatureWrapper,
      final XMLGregorianCalendar validationTime,
      final SignedObject signedObject,
      final SimpleReport simpleReport,
      final DiagnosticData diagnosticData,
      final List<byte[]> signersDocument,
      final Policy policy,
      final List<Certificate> certificates,
      final List<Timestamp> listPOE,
      final List<Ocsp> ocsps,
      final List<Crl> crls,
      final MainIndication mainIndication,
      final SubIndication subIndication) throws VerifyResponseException {
    final IndividualReportType individualReport = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createIndividualReportType();
    individualReport.setDetails(ObjectFactoryUtils.FACTORY_OASIS_CORE_1.createAnyType());
    final ValidationObjectListType validationObjectListType = validationObjectsBuilderService.build(
        signedObject,
        signersDocument,
        certificates,
        listPOE,
        ocsps,
        crls
    );

    addIndividualReportAttributes(signatureWrapper, validationTime, signedObject, simpleReport,
        diagnosticData, signersDocument, policy, mainIndication, subIndication, individualReport,
        validationObjectListType);
    if (!validationObjectListType.getValidationObject().isEmpty()) {
      final ValidationObjectList validationObjectList = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
          .createValidationObjectList(validationObjectListType);
      individualReport.getDetails().getAny().add(validationObjectList);
    }
    ValidationReportData validationReportData = validationReportDataBuilderService
        .generate(signatureWrapper, policy, diagnosticData, simpleReport, mainIndication,
            subIndication, validationObjectListType);
    individualReport.getDetails().getAny().add(validationReportData);

    return Collections.singletonList(individualReport);
  }

  private void addIndividualReportAttributes(SignatureWrapper signatureWrapper,
      XMLGregorianCalendar validationTime,
      SignedObject signedObject,
      SimpleReport simpleReport,
      DiagnosticData diagnosticData,
      List<byte[]> signersDocument,
      Policy policy,
      MainIndication mainIndication,
      SubIndication subIndication,
      IndividualReportType individualReport,
      ValidationObjectListType validationObjectListType)
      throws VerifyResponseException {
    setSignatureIdentificationElement(signedObject.getContent(), individualReport);
    setValidatorInformation(individualReport);
    setSignatureValidationStatus(mainIndication, subIndication, individualReport);
    addValidationConstraints(policy.getContent(), policy.getUrl(), individualReport);
    Optional<XMLGregorianCalendar> optionalPoETime = getPoETime(signatureWrapper);
    if (optionalPoETime.isPresent()) {
      addSignatureValidationTimeInfo(validationTime, optionalPoETime.get(), individualReport);
    } else {
      addSignatureValidationTimeInfo(validationTime, individualReport);
    }

    addSignersDocuments(signersDocument, individualReport, validationObjectListType);

    Optional<SignatureAttributes> signatureAttributesOptional = getSignatureAttributes(
        signedObject);
    if (signatureAttributesOptional.isPresent()) {
      addSignatureAttributes(signatureAttributesOptional.get().getSignedProperties(),
          signatureAttributesOptional.get().getUnsignedProperties(), individualReport,
          validationObjectListType);
    }

    // 5.2.9 Signer information
    if (!(mainIndication == MainIndication.INDETERMINATE
        && subIndication == SubIndication.NO_SIGNING_CERTIFICATE_FOUND)) {
      SignerInformation signerInformation = getSignerInformation(diagnosticData, signatureWrapper);
      addSignerInformation(signerInformation.getDistinguishedName(),
          signerInformation.getBase64Encoded(),
          signerInformation.getPseudonym() != null,
          individualReport,
          validationObjectListType);
    }

    SignatureQualification signatureQualification = getSignatureQualityElement(simpleReport,
        signatureWrapper);
    addSignatureQuality(signatureQualification, individualReport);

    addValidationProcessInfo(individualReport);
  }

  /**
   * Signature Identification Element <br/> <b>MANDATORY</b> <br/><br/> Add a Signature
   * Identification Element into the Signature Validation Report. <br> This element shall be present
   * and shall identify the signature that has been the scope of the validation.
   *
   * @param signedObject The signature or the signed document containing the signature.
   * @throws IndividualReportException whenever an error occurs when adding the Signature
   * Identification Element to the Signature Validation Report
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.2 & 5.2.2
   */
  public void setSignatureIdentificationElement(byte[] signedObject,
      IndividualReportType individualReport)
      throws IndividualReportException {
    // ETSI TS 119 102-2
    // Clause 5.2.2
    // It shall contain at least one of the following child-elements:
    // • To identify the signature by the DTBSR, the <XAdES:DigestAlgAndValue> attribute;
    // • To identify the signature by the digital signature value, a <ds:SignatureValue> element; and
    // • To identify the signature by an identifier or other elements, the Other-element.
    SignedObjectIdentifierType signedObjectIdentifierType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createSignedObjectIdentifierType();

    // OASIS DSS v1.0 Profile for Comprehensive Multi-Signature Verification Reports Version 1.0
    // Clause 3.3
    // <DigestAlgAndValue> [Optional]
    // This element contains the hash value of the signature or validation data under consideration, where
    // the signed object itself (e.g. the <ds:Signature>-element in case of an XML-signature according to [RFC3275],
    // the SignedData-structure in case of a CMS-signature according to [RFC3852] [...])
    // serves as input for the hash-calculation.
    // The structure of the DigestAlgAndValueType is defined in [XAdES].
    // NOTE: For XadES, the <ds:Signature>-element; it is the whole XML-signature for detached and enveloping but NOT for enveloped (this why it could be interesting to have the SignaturePtr on <ds:Signature> in case of enveloped signature)
    // NOTE: For CadES, the SignedData; it is the whole CMS-signature file
    DigestAlgAndValueType digestAndValue;
    try {
      digestAndValue = this.createDigestAlgAndValue(signedObject);
    } catch (MessageDigestException e) {
      throw new IndividualReportException("Internal error", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    signedObjectIdentifierType.setDigestAlgAndValue(digestAndValue);

    // ETSI TS 119 102-2
    // Clause 5.2.2.1
    // If the validation is only based on the Data to be signed formatted (DTBSF) or Data to be signed representation (DTBSR),
    // the <Other> element in the SignedObjectIdentifier element specified in clause 3.3 of the OASIS profile
    // shall contain a ValidationBasedOnHash Element.
    // AnyType any = new AnyType();
    // any.getAny().add(new ValidationBasedOnHash());
    // signedObjectIdentifierType.setOther(any);

    individualReport.setSignedObjectIdentifier(signedObjectIdentifierType);
  }

  /**
   * Validator Information <br/> <b>OPTIONAL</b> <br/><br/> Add a Validator Information into the
   * Signature Validation Report. <br> When present, this element shall contain information on the
   * identity of the entity validating the signature and creating the validation report.
   *
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.3 & 5.2.3
   */
  public void setValidatorInformation(IndividualReportType individualReport) {
    JAXBElement<String> subjectName = ObjectFactoryUtils.FACTORY_XML_DSIG
        .createX509DataTypeX509SubjectName(SubjectNameInfo.SUBJECT_NAME);

    X509DataType x509DataType = ObjectFactoryUtils.FACTORY_XML_DSIG.createX509DataType();
    x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(subjectName);

    IdentifierType identifierType = ObjectFactoryUtils.FACTORY_OASIS_DSSX.createIdentifierType();
    identifierType.setX509Data(x509DataType);

    Identifier identifier = ObjectFactoryUtils.FACTORY_OASIS_DSSX.createIdentifier(identifierType);

    individualReport.getDetails().getAny().add(identifier);
  }

  /**
   * Signature Validation Status Indication <br/> <b>MANDATORY</b> <br/><br/> Add a Signature
   * Validation Status Indication element into the Signature Validation Report. <br> This element
   * shall be present and it shall contain the status on the full validation of the signature in the
   * context of a particular signature validation policy.
   *
   * @param mainIndication main indication indicating whether TOTAL-PASSED, TOTAL-FAILED or
   * INDETERMINATE
   * @param subIndication sub indication that shall clearly identify the reason for the main status
   * indication
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.4 & 5.2.4
   */
  public void setSignatureValidationStatus(MainIndication mainIndication,
      SubIndication subIndication,
      IndividualReportType individualReport) {
    Result result = ObjectFactoryUtils.FACTORY_OASIS_CORE_1.createResult();
    result.setResultMajor(mainIndication.getURI());
    if (subIndication != null && subIndication.getURI() != null) {
      result.setResultMinor(subIndication.getURI());

      // set message
      InternationalStringType internationalStringType = ObjectFactoryUtils.FACTORY_OASIS_CORE_1
          .createInternationalStringType();
      internationalStringType.setLang("en");
      internationalStringType.setValue(subIndication.getMessage());
      result.setResultMessage(internationalStringType);
    }
    individualReport.setResult(result);
  }

  /**
   * Validation Constraints <br/> <b>MANDATORY</b> <br/><br/> Add a Validation Constraints element
   * into the Signature Validation Report. <br> This element shall be present and shall specify the
   * set of validation constraints that have been driving the validation process, irrespective of
   * the way the constraints have been defined.
   *
   * @param policyBytes a byte array containing the policy applied during validation
   * @param policyID a unique identifier of the policy (i.e. its URI)
   * @throws IndividualReportException whenever an error occurs when adding the Validation
   * Constraints element to the Signature Validation Report
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.5 & 5.2.5
   */
  public void addValidationConstraints(byte[] policyBytes, String policyID,
      IndividualReportType individualReport)
      throws IndividualReportException {
    eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.IdentifierType identifierType = ObjectFactoryUtils.FACTORY_XADES_132
        .createIdentifierType();
    identifierType.setValue(policyID);

    ObjectIdentifierType objectIdentifierType = ObjectFactoryUtils.FACTORY_XADES_132
        .createObjectIdentifierType();
    objectIdentifierType.setIdentifier(identifierType);

    DigestAlgAndValueType digestAlgAndValue;
    try {
      digestAlgAndValue = this.createDigestAlgAndValue(policyBytes);
    } catch (MessageDigestException e) {
      throw new IndividualReportException("Internal error", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    SignaturePolicyIdType signaturePolicyIdType = ObjectFactoryUtils.FACTORY_XADES_132
        .createSignaturePolicyIdType();
    signaturePolicyIdType.setSigPolicyId(objectIdentifierType);
    signaturePolicyIdType.setSigPolicyHash(digestAlgAndValue);

    SignaturePolicyIdentifierType signaturePolicyIdentifier = ObjectFactoryUtils.FACTORY_XADES_132
        .createSignaturePolicyIdentifierType();
    signaturePolicyIdentifier.setSignaturePolicyId(signaturePolicyIdType);

    ValidationConstraintsType validationConstraintsType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationConstraintsType();
    validationConstraintsType.setSignaturePolicyIdentifier(signaturePolicyIdentifier);

    ValidationConstraints validationConstraints = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationConstraints(validationConstraintsType);

    individualReport.getDetails().getAny().add(validationConstraints);
  }

  /**
   * Signature Validation Time Info <br/> <b>MANDATORY</b> <br/><br/> Add a Signature Validation
   * Time Info element into the Signature Validation Report. <br> This element shall be present and
   * shall contain the date and time the validation was performed, and the date and time for which a
   * PoE of the signature has been identified and the validation status has been determined.
   *
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.6 & 5.2.6
   */
  public void addSignatureValidationTimeInfo(XMLGregorianCalendar validationTime,
      IndividualReportType individualReport) {
    VerificationTimeInfoType verificationTimeInfoType = ObjectFactoryUtils.FACTORY_OASIS_CORE_1
        .createVerificationTimeInfoType();
    verificationTimeInfoType.setVerificationTime(validationTime);

    VerificationTimeInfo verificationTimeInfo = ObjectFactoryUtils.FACTORY_OASIS_CORE_1
        .createVerificationTimeInfo(verificationTimeInfoType);

    individualReport.getDetails().getAny().add(verificationTimeInfo);
  }

  /**
   * Signature Validation Time Info <br/> <b>MANDATORY</b> <br/><br/> Add a Signature Validation
   * Time Info element into the Signature Validation Report. <br> This element shall be present and
   * shall contain the date and time the validation was performed, and the date and time for which a
   * PoE of the signature has been identified and the validation status has been determined.
   *
   * @param poeTime the date and time for which a PoE of the signature has been identified and the
   * validation status has been determined
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.6 & 5.2.6
   */
  public void addSignatureValidationTimeInfo(XMLGregorianCalendar validationTime,
      XMLGregorianCalendar poeTime,
      IndividualReportType individualReport) {
    VerificationTimeInfoType verificationTimeInfoType = ObjectFactoryUtils.FACTORY_OASIS_CORE_1
        .createVerificationTimeInfoType();

    verificationTimeInfoType.setVerificationTime(validationTime);

    if (poeTime != null) {
      AdditionalTimeInfoType additionalTimeInfo = ObjectFactoryUtils.FACTORY_OASIS_CORE_1
          .createAdditionalTimeInfoType();
      additionalTimeInfo.setValue(poeTime);
      additionalTimeInfo.setType(BestSignatureTimeURI.BEST_SIGNATURE_TIME_URI);
      verificationTimeInfoType.getAdditionalTimeInfo().add(additionalTimeInfo);
    }

    VerificationTimeInfo verificationTimeInfo = ObjectFactoryUtils.FACTORY_OASIS_CORE_1
        .createVerificationTimeInfo(verificationTimeInfoType);

    individualReport.getDetails().getAny().add(verificationTimeInfo);
  }

  /**
   * Signer's Document <br/> <b>MANDATORY</b> <br/><br/> Add a Signer's Document element into the
   * Signature Validation Report. <br> This element shall be present and shall identify the data
   * that has been covered by the signature (DTBS). The DTBS consists of the Signer’s Data (SD) or
   * the Signer's document representation (SDR) and the signature attributes selected to be signed
   * together with the SD or SDR.
   *
   * @param base64SignersDocument base64 representation of the data to be signed (DTBS)
   * @throws IndividualReportException Whenever the signer's document represented by {@code
   * base64SignersDocument} cannot be added to the Signature Validation Report
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.7 & 5.2.7
   */
  private void addSignersDocument(final byte[] base64SignersDocument,
      final IndividualReportType individualReport,
      final ValidationObjectListType validationObjectListType)
      throws IndividualReportException {
    Optional<ValidationObjectType> optionalValidationObjectType = validationObjectsBuilderService
        .findByBase64(base64SignersDocument, ValidationObjectTypeId.OTHER,
            validationObjectListType);
    if (!optionalValidationObjectType.isPresent()) {
      String errorMessage = "Signer's document is missing in the Validation Objects";

      throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    ValidationObjectType validationObjectType = optionalValidationObjectType.get();
    VOReferenceType voReference = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createVOReferenceType();
    voReference.getVOReference().add(validationObjectType);

    SignersDocumentType signersDocumentType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createSignersDocumentType();
    try {
      signersDocumentType
          .setDigestAlgAndValue(this.createDigestAlgAndValue(Base64.decode(base64SignersDocument)));
    } catch (MessageDigestException e) {

      throw new IndividualReportException("Internal error", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    signersDocumentType.setSignersDocument(voReference);

    SignersDocument signersDocument = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createSignersDocument(signersDocumentType);

    individualReport.getDetails().getAny().add(signersDocument);
  }

  /**
   * Signer's Document <br/> <b>MANDATORY</b> <br/><br/> Add a Signer's Document element into the
   * Signature Validation Report. <br> This element shall be present and shall identify the data
   * that has been covered by the signature (DTBS). The DTBS consists of the Signer’s Data (SD) or
   * the Signer's document representation (SDR) and the signature attributes selected to be signed
   * together with the SD or SDR.
   *
   * @param signersDocuments list of base64 representation of the data to be signed (DTBS)
   * @throws IndividualReportException Whenever the signer's document represented by {@code
   * base64SignersDocument} cannot added to the Signature Validation Report
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.7 & 5.2.7
   */
  public void addSignersDocuments(final List<byte[]> signersDocuments,
      final IndividualReportType individualReport,
      final ValidationObjectListType validationObjectListType) throws IndividualReportException {
    for (byte[] document : signersDocuments) {
      addSignersDocument(document, individualReport, validationObjectListType);
    }
  }

  /**
   * Signature Attributes <br/> <b>MANDATORY, only for XAdES</b> <br/><br/> Add a Signature
   * Attributes element into the Signature Validation Report. <br> This element shall be present
   * whenever the signature contained signature attributes. It shall consist of a list of all
   * attributes contained in the signature together with the information whether the attribute   was
   * a signed or an unsigned attribute.
   *
   * @param signedPropertiesTypeXADES attributes that was signed
   * @param unsignedPropertiesTypeXADES attributes that was unsigned
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.8 & 5.2.8
   */
  public void addSignatureAttributes(
      eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignedPropertiesType signedPropertiesTypeXADES,
      eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.UnsignedPropertiesType unsignedPropertiesTypeXADES,
      IndividualReportType individualReport,
      final ValidationObjectListType validationObjectListType) throws IndividualReportException {

    PropertiesType propertiesType = ObjectFactoryUtils.FACTORY_OASIS_DSSX.createPropertiesType();

    propertiesType.setSignedProperties(xAdESPropertiesMapperService
        .mapSignedProperties(signedPropertiesTypeXADES, validationObjectListType));
    // TODO: timestamp does not work and make the validation failed
    // propertiesType.setUnsignedProperties(xAdESPropertiesMapperService.mapUnsignedProperties(unsignedPropertiesTypeXADES, validationObjectListType));

    individualReport.getDetails().getAny()
        .add(ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createSignatureAttributes(propertiesType));
  }

  /**
   * Signature Information <br/> <b>MANDATORY</b> <br/><br/> Add a Signature Information element
   * into the Signature Validation Report. <br> This element shall be present. It shall contain a
   * reference to an object in the Signature Validation Objects element. The object referenced shall
   * be the certificate that has been identified as the signer’s certificate and that contains the
   * unique set of data representing the signer. It may contain a human readable representation of
   * the signer. When a pseudonym has been used at the time of signing, it shall contain an element
   * indicating whether that a pseudonym has been used at the time of signing; otherwise, it may
   * contain such element.
   *
   * @param signer human readable representation of the signer
   * @param x509CertificateBase64 base64 representation of the signer's certificate
   * @param pseudonymUsed a boolean indicating that a pseudonym was used or not in the certificate
   * @throws ValidationObjectException Whenever the certificate represented by {@code
   * x509CertificateBase64} cannot be added to the Signature Validation Report
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.9 & 5.2.9
   */
  public void addSignerInformation(final String signer,
      final byte[] x509CertificateBase64,
      final boolean pseudonymUsed,
      final IndividualReportType individualReport,
      final ValidationObjectListType validationObjectListType) throws ValidationObjectException {
    Optional<ValidationObjectType> optionalValidationObjectType = validationObjectsBuilderService
        .findByBase64(x509CertificateBase64, ValidationObjectTypeId.CERTIFICATE,
            validationObjectListType);

    if (!optionalValidationObjectType.isPresent()) {
      String errorMessage = "Signer's certificate is missing in the Validation Objects";

      throw new ValidationObjectException(errorMessage, ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    } else {
      ValidationObjectType validationObjectType = optionalValidationObjectType.get();
      VOReferenceType voReference = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
          .createVOReferenceType();
      voReference.getVOReference().add(validationObjectType);

      SignerInformationType signerInformationType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
          .createSignerInformationType();
      signerInformationType.setPseudonym(pseudonymUsed);
      signerInformationType.setSigner(signer);
      signerInformationType.setSignerCertificate(voReference);

      eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignerInformation signerInformation = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
          .createSignerInformation(signerInformationType);

      individualReport.getDetails().getAny().add(signerInformation);
    }
  }

  /**
   * Signature Quality <br/> <b>OPTIONAL</b> <br/><br/> Add a Signature Quality element into the
   * Signature Validation Report. <br> When present, this element shall contain information
   * supporting the quality of the signature.
   *
   * @param signatureQualification quality of the signature
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.10 & 5.2.10
   */
  public void addSignatureQuality(SignatureQualification signatureQualification,
      IndividualReportType individualReport) {
    if (signatureQualification != null) {
      SignatureQualityType signatureQualityType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
          .createSignatureQualityType();
      signatureQualityType.setSignatureQualityInformation(signatureQualification.getURI());

      SignatureQuality signatureQuality = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
          .createSignatureQuality(signatureQualityType);

      individualReport.getDetails().getAny().add(signatureQuality);
    }
  }

  /**
   * Signature Validation Process Information <br/> <b>MANDATORY</b> <br/><br/> Add a Signature
   * Validation Process Information element into the Signature Validation Report. <br> This element
   * shall be present and shall contain one or more of: <ul> <li>An identifier indicating the
   * validation process that has been used in validation.</li> <li>[0-1] Information identifying the
   * validation service policy, when applicable</li> <li>[0-1] Information identifying the
   * validation service practice statement, when applicable</li> <li>[0-1] Information on
   * augmentation of the signature, when applicable</li> <li>[0-1] Other information provided by the
   * SVP</li> </ul>
   *
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.11 & 5.2.11
   */
  public void addValidationProcessInfo(IndividualReportType individualReport) {
    SignatureValidationProcessType signatureValidationProcessType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createSignatureValidationProcessType();
    signatureValidationProcessType
        .setSignatureValidationProcessID(SignatureValidationProcessID.LTA.getURI());
    // Didn't add the Augmentation info since there is not enough information to do this.

    SignatureValidationProcess signatureValidationProcess = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createSignatureValidationProcess(signatureValidationProcessType);

    individualReport.getDetails().getAny().add(signatureValidationProcess);
  }

  /**
   * Used to compute a digest value on a byte array depending on the recommended digest algorithm
   *
   * @param toBeDigested byte array to be digested
   * @return an object representing the digest value and the digest algorithm used to compute the
   * digest value
   */
  private DigestAlgAndValueType createDigestAlgAndValue(byte[] toBeDigested)
      throws MessageDigestException {

    try {
      final String digestAlgo = cryptoProperties.getDigestAlgorithm();
      MessageDigest messageDigest = MessageDigest.getInstance(digestAlgo);
      byte[] digestValue = messageDigest.digest(toBeDigested);
      byte[] digestValueBase64 = Base64.encode(digestValue);

      DigestMethodType digestMethod = ObjectFactoryUtils.FACTORY_XML_DSIG.createDigestMethodType();
      digestMethod.setAlgorithm(digestAlgo);

      DigestAlgAndValueType digestAndValue = ObjectFactoryUtils.FACTORY_XADES_132
          .createDigestAlgAndValueType();
      digestAndValue.setDigestValue(digestValueBase64);
      digestAndValue.setDigestMethod(digestMethod);
      return digestAndValue;
    } catch (NoSuchAlgorithmException e) {
      throw new MessageDigestException("Unable to use digest algorithm from properties",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
  }

  /**
   * Get the date and time for which a PoE of the signature has been identified and the validation
   * status has been determined, if it exists.
   *
   * @param signatureWrapper object wrapping the signature
   * @return date and time for which a PoE of the signature has been identified
   */
  private Optional<XMLGregorianCalendar> getPoETime(SignatureWrapper signatureWrapper) {
    XMLGregorianCalendar poeTime = null;

    if (signatureWrapper.getSignatureFormat().endsWith("LTA") || signatureWrapper
        .getSignatureFormat().endsWith("LT")
        ) {
      GregorianCalendar c = new GregorianCalendar();
      c.setTime(signatureWrapper.getDateTime());
      try {
        poeTime = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
      } catch (DatatypeConfigurationException e) {
        // TODO: if the gregorian type builder cannot be instantiated then INTERNAL SERVER ERROR or just skip as poeTime is OPTIONAL ?
        return Optional.empty();
      }
    }
    return Optional.ofNullable(poeTime);
  }

  /**
   * Get all attributes contained in the signature together with the information whether the
   * attribute was a signed or an unsigned attribute.
   *
   * @return signed and unsigned attributes
   * @throws IndividualReportException whenever an error occurs while parsing the signature's
   * atributes
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.8 & 5.2.8
   */
  private Optional<SignatureAttributes> getSignatureAttributes(
      final SignedObject signature) throws IndividualReportException {
    if (signature.getFormat().equals(SignedObjectFormat.XML)) {
      try {
        byte[] signatureBytes = signature.getContent();

        if (signature.getType().isEnveloped()) {
          DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
          DocumentBuilder builder = factory.newDocumentBuilder();
          Document doc = builder.parse(new ByteArrayInputStream(signature.getContent()));
          XPathFactory xPathfactory = XPathFactory.newInstance();
          XPath xpath = xPathfactory.newXPath();
          NodeList nodeList = (NodeList) xpath
              .evaluate("//*/Signature", doc, XPathConstants.NODESET);
          Transformer xformer = TransformerFactory.newInstance().newTransformer();
          ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
          xformer
              .transform(new DOMSource(nodeList.item(0)), new StreamResult(byteArrayOutputStream));
          signatureBytes = byteArrayOutputStream.toByteArray();
        }

        Unmarshaller unmarshaller = new MarshallerSingleton().getUnmarshaller(
            eu.futuretrust.vals.jaxb.oasis.xmldsig.core.Signature.class);
        eu.futuretrust.vals.jaxb.oasis.xmldsig.core.Signature unMarshalledSignature = (eu.futuretrust.vals.jaxb.oasis.xmldsig.core.Signature) unmarshaller
            .unmarshal(new ByteArrayInputStream(signatureBytes));
        for (ObjectType o : unMarshalledSignature.getValue().getObject()) {
          for (Object o1 : o.getContent()) {
            if (o1.getClass().equals(QualifyingProperties.class)) {
              QualifyingProperties qualifyingProperties = (QualifyingProperties) o1;
              SignatureAttributes signatureAttributes = new SignatureAttributes();
              signatureAttributes
                  .setSignedProperties(qualifyingProperties.getValue().getSignedProperties());
              signatureAttributes
                  .setUnsignedProperties(qualifyingProperties.getValue().getUnsignedProperties());
              return Optional.of(signatureAttributes);
            }
          }
        }
      } catch (JAXBException | TransformerException | ParserConfigurationException | IOException | XPathExpressionException | SAXException e) {
        e.printStackTrace();
        throw new IndividualReportException("Could not gather the signature attributes",
            ResultMajor.REQUESTER_ERROR, ResultMinor.GENERAL_ERROR);
      }
    }
    return Optional.empty();
  }

  /**
   * Get the certificate that has been identified as the signer’s certificate and that contains the
   * unique set of data representing the signer, a human readable representation of the signer and
   * possibly a pseudonym.
   *
   * @return an object representing the signer information
   * @throws VerifyResponseException whenever the Verify Response cannot be created because of an
   * internal server error
   * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019102-2v012.pdf">ETSI TS 119
   * 102-2</a> clauses 4.2.9 & 5.2.9
   */
  private SignerInformation getSignerInformation(
      final DiagnosticData diagnosticData,
      final SignatureWrapper signatureWrapper)
      throws VerifyResponseException {
    if (!signatureWrapper.getSigningCertificateId().equals("")) {

      try {
        CertificateWrapper certificateWrapper = diagnosticData
            .getUsedCertificateById(signatureWrapper.getSigningCertificateId());
        DSSCertificateWrapperParser dssCertificateWrapperParser = new DSSCertificateWrapperParser();
        XmlCertificate xmlCertificate = dssCertificateWrapperParser
            .getXmlCertificateField(certificateWrapper);
        byte[] certToBase64 = dssCertificateWrapperParser.getCertificateBase64(certificateWrapper);

        SignerInformation signerInformation = new SignerInformation(certToBase64);

        InputStream in = new ByteArrayInputStream(Base64.decode(certToBase64));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate signerCert = (X509Certificate) certFactory.generateCertificate(in);

        signerInformation.setDistinguishedName(signerCert.getSubjectDN().getName());
        signerInformation.setPseudonym(xmlCertificate.getPseudonym());
        return signerInformation;
      } catch (DSSParserException | CertificateException e) {
        String errorMessage = "Error while retrieving Signer Information" + e.getMessage();

        throw new VerifyResponseException(errorMessage, ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
    } else {
      String errorMessage = "Error while retrieving Signer Information";

      throw new VerifyResponseException(errorMessage,
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
  }

  private SignatureQualification getSignatureQualityElement(final SimpleReport simpleReport,
      final SignatureWrapper signatureWrapper) {

    eu.europa.esig.dss.validation.SignatureQualification signatureQualification = simpleReport
        .getSignatureQualification(signatureWrapper.getId());
    return new SignatureQualification(signatureQualification.getLabel());
  }

}
