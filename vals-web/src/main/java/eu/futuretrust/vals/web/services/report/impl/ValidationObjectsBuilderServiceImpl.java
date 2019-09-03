package eu.futuretrust.vals.web.services.report.impl;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.PoEType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.VOReferenceType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectRepresentationType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CRLValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.OCSPValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.TimeStampValidityType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import eu.futuretrust.vals.protocol.exceptions.ValidationObjectException;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.output.Certificate;
import eu.futuretrust.vals.protocol.output.Crl;
import eu.futuretrust.vals.protocol.output.DigestAlgoAndValue;
import eu.futuretrust.vals.protocol.output.Ocsp;
import eu.futuretrust.vals.protocol.output.Timestamp;
import eu.futuretrust.vals.web.services.report.ValidationObjectsBuilderService;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

@Service
public class ValidationObjectsBuilderServiceImpl implements ValidationObjectsBuilderService {

  public ValidationObjectListType build(
      final SignedObject signature,
      final List<byte[]> signersDocument,
      final List<Certificate> certificates,
      final List<Timestamp> listPOE,
      final List<Ocsp> ocsps,
      final List<Crl> crls) throws ValidationObjectException {

    final ValidationObjectListType validationObjectListType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationObjectListType();

    addValidationObjects(validationObjectListType, Base64.encode(signature.getContent()),
        signersDocument, certificates,
        listPOE, ocsps, crls);

    for (Timestamp timestamp : listPOE)
    {
      Optional<ValidationObjectType> maybeTimestamp = findByBase64(timestamp.getBase64(),
          ValidationObjectTypeId.TIMESTAMP,
          validationObjectListType);
      if (maybeTimestamp.isPresent()) {
        ValidationObjectType timestampValidationObject = maybeTimestamp.get();
        for (byte[] voToFindByBase64 : timestamp.getReferencedObjectsByBase64()) {
          Optional<ValidationObjectType> maybe = findByBase64(voToFindByBase64,
              validationObjectListType);
          if (maybe.isPresent()) {
            PoEType poeType = getPoEType(timestamp, timestampValidationObject);
            maybe.get().setPoE(poeType);
          }
        }
        for (DigestAlgoAndValue digestAlgoAndValue : timestamp.getReferencedObjectsByHash()) {
          Optional<ValidationObjectType> maybe = findByHash(digestAlgoAndValue.getValue(),
              digestAlgoAndValue.getDigestAlgo(), validationObjectListType.getValidationObject());
          if (maybe.isPresent()) {
            PoEType poeType = getPoEType(timestamp, timestampValidationObject);
            maybe.get().setPoE(poeType);
          }
        }
      } else {
        throw new ValidationObjectException("Internal error", ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
    }
    return validationObjectListType;
  }

  private void addValidationObjects(ValidationObjectListType validationObjectListType,
      final byte[] signedData,
      final List<byte[]> signersDocument,
      final List<Certificate> certificates,
      final List<Timestamp> timestamps,
      final List<Ocsp> ocsps,
      final List<Crl> crls) {
    addSignersDocument(signersDocument, validationObjectListType);
    addSignedDataObject(signedData, validationObjectListType);
    addCertificate(certificates, validationObjectListType);
    addTimestamp(timestamps, validationObjectListType);
    addOcsp(ocsps, validationObjectListType);
    addCrl(crls, validationObjectListType);
  }

  private PoEType getPoEType(Timestamp timestamp,
      ValidationObjectType timestampValidationObject) {
    PoEType poeType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createPoEType();
    VOReferenceType voReferenceType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createVOReferenceType();
    voReferenceType.getVOReference().add(timestampValidationObject);
    poeType.setPoEObject(voReferenceType);
    poeType.setPoETime(
        XMLGregorianCalendarBuilder.createXMLGregorianCalendar(timestamp.getPoeTime()));
    return poeType;
  }

  /**
   * Find the Validation Object corresponding to the {@code base64} parameter, if it exists
   *
   * @param base64 Base64 value of the Validation Object
   * @return the Validation Objects corresponding to the {@code base64} parameter, or {@code
   * Optional.empty()}
   */
  public Optional<ValidationObjectType> findByBase64(byte[] base64,
      final ValidationObjectListType validationObjectListType) {
    return findByBase64(base64, findAll(validationObjectListType));
  }

  /**
   * Find the Validation Object corresponding to the {@code base64} parameter in Validation Objects
   * of type {@link ValidationObjectTypeId} {@code voType}, if it exists
   *
   * @param base64 Base64 value of the Validation Object
   * @param voType type of the Validation Objects to be filtered
   * @return the Validation Objects corresponding to the {@code base64} parameter, or {@code
   * Optional.empty()}
   */
  public Optional<ValidationObjectType> findByBase64(byte[] base64,
      ValidationObjectTypeId voType,
      final ValidationObjectListType validationObjectListType) {
    return findByBase64(base64, findAll(voType, validationObjectListType));
  }

  /**
   * Get all the Validation Objects registered in the builder
   *
   * @return list of Validation Objects
   */
  public List<ValidationObjectType> findAll(
      final ValidationObjectListType validationObjectListType) {
    return validationObjectListType.getValidationObject();
  }

  /**
   * Get all the Validation Objects of type {@link ValidationObjectTypeId} {@code voType} registered
   * in the builder
   *
   * @param voType type of the Validation Objects to be filtered
   * @return list of Validation Objects of type {@link ValidationObjectTypeId} {@code voType}
   */
  public List<ValidationObjectType> findAll(ValidationObjectTypeId voType,
      final ValidationObjectListType validationObjectListType) {
    return findAll(validationObjectListType).stream()
        .filter(vo -> vo.getObjectType().equals(voType.getURI()))
        .collect(Collectors.toList());
  }

  /**
   * Find the Validation Object corresponding to the {@code uri} parameter, if it exists
   *
   * @param uri URI of the Validation Object
   * @return the Validation Objects corresponding to the {@code uri} parameter, or {@code
   * Optional.empty()}
   */
  public Optional<ValidationObjectType> findByUri(String uri,
      final ValidationObjectListType validationObjectListType) {
    return findByUri(uri, findAll(validationObjectListType));
  }

  /**
   * Find the Validation Object corresponding to the {@code object} parameter, if it exists
   *
   * @param object object to find as a "direct" object
   * @return the Validation Objects corresponding to the {@code object} parameter, or {@code
   * Optional.empty()}
   */
  public Optional<ValidationObjectType> findByDirect(Object object,
      final ValidationObjectListType validationObjectListType) {
    return findByDirect(object, findAll(validationObjectListType));
  }

  /**
   * Add a Certificate into the Validation Objects
   *
   * @param x509CertificateBase64 base64 representation of the X509 Certificate
   * @param validity {@link CertificateValidityType} which represents the validity of the
   * Certificate
   */
  public void addCertificate(byte[] x509CertificateBase64,
      CertificateValidityType validity,
      final ValidationObjectListType validationObjectListType) {
    ValidationObjectType validationObject = create(ValidationObjectTypeId.CERTIFICATE,
        x509CertificateBase64);
    validationObject.setIndividualCertificateReport(validity);
    validationObjectListType.getValidationObject().add(validationObject);
  }

  /**
   * Add a Certificate into the Validation Objects
   *
   * @param certificate object representing a Certificate (must contain the base64 value and the
   * validity)
   */
  public void addCertificate(Certificate certificate,
      final ValidationObjectListType validationObjectListType) {
    addCertificate(certificate.getBase64(), certificate.getValidity(), validationObjectListType);
  }

  /**
   * Add all the Certificates within the {@code certificates} list in parameter into the validation
   * objects
   *
   * @param certificates list of Certificates Validation Objects
   */
  public void addCertificate(List<Certificate> certificates,
      final ValidationObjectListType validationObjectListType) {
    certificates.forEach(c -> addCertificate(c, validationObjectListType));
  }

  /**
   * Add a Timestamp into the Validation Objects
   *
   * @param timestampBase64 : a base64 representation of the Timestamp
   * @param validity : a {@link TimeStampValidityType} which represents the validity of the
   * Timestamp
   */
  public void addTimestamp(byte[] timestampBase64, TimeStampValidityType validity,
      final ValidationObjectListType validationObjectListType) {
    ValidationObjectType validationObject = create(ValidationObjectTypeId.TIMESTAMP,
        timestampBase64);
    validationObject.setIndividualTimeStampReport(validity);
    validationObjectListType.getValidationObject().add(validationObject);
  }

  /**
   * Add a Timestamp into the Validation Objects
   *
   * @param timestamp object representing a Timestamp (must contain the base64 value and the
   * validity)
   */
  public void addTimestamp(final Timestamp timestamp,
      final List<Timestamp> listPOE,
      final ValidationObjectListType validationObjectListType) {
    listPOE.add(timestamp);
    addTimestamp(timestamp.getBase64(), timestamp.getValidity(), validationObjectListType);
  }

  /**
   * Add all the Timestamps within the {@code timestamps} list in parameter into the validation
   * objects
   *
   * @param timestamps list of Timestamps Validation Objects
   */
  public void addTimestamp(final List<Timestamp> timestamps,
      final ValidationObjectListType validationObjectListType) {
    timestamps
        .forEach(ts -> addTimestamp(ts.getBase64(), ts.getValidity(), validationObjectListType));
  }

  /**
   * Add a Signer's Document into the Validation Objects
   *
   * @param signersDocumentBase64 a base64 representation of the signer's document
   */
  public void addSignersDocument(byte[] signersDocumentBase64,
      final ValidationObjectListType validationObjectListType) {
    ValidationObjectType validationObject = create(ValidationObjectTypeId.OTHER,
        signersDocumentBase64);
    validationObjectListType.getValidationObject().add(validationObject);
  }

  /**
   * Add all the Signer's Documents within the {@code signersDocuments} list in parameter into the
   * Validation Objects
   *
   * @param signersDocumentsBase64 list of base64 representations of Signer's Documents
   */
  public void addSignersDocument(List<byte[]> signersDocumentsBase64,
      final ValidationObjectListType validationObjectListType) {
    signersDocumentsBase64.forEach(sd -> addSignersDocument(sd, validationObjectListType));
  }

  /**
   * Add a Signed Data Object into the Validation Objects
   *
   * @param signedDataObjectBase64 a base64 representation of the Signed Data Object
   */
  public void addSignedDataObject(byte[] signedDataObjectBase64,
      final ValidationObjectListType validationObjectListType) {
    ValidationObjectType validationObject = create(ValidationObjectTypeId.OTHER,
        signedDataObjectBase64);
    validationObjectListType.getValidationObject().add(validationObject);
  }

  /**
   * Add a CRL in the Validation Objects
   *
   * @param base64 the encoding of the CRL
   * @param validity a {@link CRLValidityType} which represents the validity of the CRL
   */
  public void addCrl(final byte[] base64,
      final CRLValidityType validity,
      final ValidationObjectListType validationObjectListType) {
    ValidationObjectType validationObjectType = create(ValidationObjectTypeId.CRL, base64);
    validationObjectType.setIndividualCRLReport(validity);
    validationObjectListType.getValidationObject().add(validationObjectType);
  }

  /**
   * Add a CRL in the Validation Objects
   *
   * @param crl object representing a CRL (must contain the URI and the validity)
   */
  public void addCrl(Crl crl,
      final ValidationObjectListType validationObjectListType) {
    addCrl(crl.getBase64(), crl.getValidity(), validationObjectListType);
  }

  /**
   * Add all the CRL within the {@code crlList} list in parameter into the Validation Objects
   *
   * @param crlList list of CRL Validation Objects
   */
  public void addCrl(final List<Crl> crlList,
      final ValidationObjectListType validationObjectListType) {
    crlList.forEach(crl -> addCrl(crl, validationObjectListType));
  }

  /**
   * Add a OCSP Response in the Validation Objects
   *
   * @param base64 the OCSP response encoded in base64
   * @param validity a {@link OCSPValidityType} which represents the validity of the OCSP Response
   */
  public void addOcsp(final byte[] base64,
      final OCSPValidityType validity,
      final ValidationObjectListType validationObjectListType) {
    ValidationObjectType validationObject = create(ValidationObjectTypeId.OCSPRESPONSE, base64);
    validationObject.setIndividualOCSPReport(validity);
    validationObjectListType.getValidationObject().add(validationObject);
  }

  /**
   * Add a OCSP Response in the Validation Objects
   *
   * @param ocsp object representing a OCSP Response (must contain the URI and the validity)
   */
  public void addOcsp(final Ocsp ocsp,
      final ValidationObjectListType validationObjectListType) {
    addOcsp(ocsp.getBase64(), ocsp.getValidity(), validationObjectListType);
  }

  /**
   * Add all the OCSP Responses within the {@code ocspList} list in parameter into the Validation
   * Objects
   *
   * @param ocspList list of OCSP Responses Validation Objects
   */
  public void addOcsp(final List<Ocsp> ocspList,
      final ValidationObjectListType validationObjectListType) {
    ocspList.forEach(ocsp -> addOcsp(ocsp, validationObjectListType));
  }

  /**
   * Create a new Validation Object
   *
   * @param voType type of the Validation Object
   * @return Validation Object that has been created
   */
  private ValidationObjectType create(ValidationObjectTypeId voType) {
    ValidationObjectType validationObjectType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationObjectType();

    // 4.3.2 Identifier
    validationObjectType.setId(UUID.randomUUID().toString());

    // 4.3.3 Object type
    validationObjectType.setObjectType(voType.getURI());

    // 4.3.5 Proof of Existence (PoE) : done during building
    // This property shall contain the time for which a proof-of-existence for this object has been determined during validation.
    // When the validation process determines multiple PoE-values for an object,
    // this element shall contain the information on the PoE providing the earliest time for the existence of the object.
    // It shall contain the time value for that proof in UTC.
    // It may contain an identifier of the signature validation object that was essential for that proof.

    return validationObjectType;
  }

  /**
   * Create a new Validation Object with Type and URI initialized
   *
   * @param voType type of the Validation Object
   * @param uri URI of the Validation Object
   * @return Validation Object that has been created
   */
  private ValidationObjectType create(ValidationObjectTypeId voType, String uri) {
    ValidationObjectType validationObjectType = create(voType);

    // 4.3.4 Validation object
    ValidationObjectRepresentationType validationObjectRepresentationType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationObjectRepresentationType();
    validationObjectRepresentationType.setURI(uri);
    validationObjectType.setValidationObject(validationObjectRepresentationType);

    return validationObjectType;
  }

  /**
   * Create a new Validation Object with Type and base64 value initialized
   *
   * @param voType type of the Validation Object
   * @param base64 base64 representation of the Validation Object
   * @return Validation Object that has been created
   */
  private ValidationObjectType create(ValidationObjectTypeId voType, byte[] base64) {
    ValidationObjectType validationObjectType = create(voType);

    // 4.3.4 Validation object
    ValidationObjectRepresentationType validationObjectRepresentationType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationObjectRepresentationType();
    validationObjectRepresentationType.setBase64(base64);
    validationObjectType.setValidationObject(validationObjectRepresentationType);

    return validationObjectType;
  }

  /**
   * Create a new Validation Object with Type and direct object representation initialized
   *
   * @param voType type of the Validation Object
   * @param object object representing the Validation Object
   * @return Validation Object that has been created
   */
  private ValidationObjectType create(ValidationObjectTypeId voType, Object object) {
    ValidationObjectType validationObjectType = create(voType);

    // 4.3.4 Validation object
    ValidationObjectRepresentationType validationObjectRepresentationType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2
        .createValidationObjectRepresentationType();
    validationObjectRepresentationType.setDirect(object);
    validationObjectType.setValidationObject(validationObjectRepresentationType);

    return validationObjectType;
  }

  /**
   * Find the Validation Object corresponding to the {@code base64} parameter in Validation Objects,
   * if it exists
   *
   * @param base64 Base64 value of the Validation Object
   * @param list list to go through
   * @return the Validation Objects corresponding to the {@code base64} parameter, or {@code
   * Optional.empty()}
   */
  private Optional<ValidationObjectType> findByBase64(byte[] base64,
      List<ValidationObjectType> list) {
    if (base64 == null) {
      return Optional.empty();
    } else {
      return list.stream()
          .filter(vo -> Objects.nonNull(vo)
              && Objects.nonNull(vo.getValidationObject())
              && Objects.nonNull(vo.getValidationObject().getBase64()))
          .filter(vo -> Arrays.equals(vo.getValidationObject().getBase64(), base64))
          .findFirst();
    }
  }

  private Optional<ValidationObjectType> findByHash(byte[] hashedValidationObject,
      String digestAlgo, List<ValidationObjectType> list) throws ValidationObjectException {
    if (hashedValidationObject == null) {
      return Optional.empty();
    } else {
      try {
        MessageDigest md = MessageDigest.getInstance(digestAlgo);

        return list.stream()
            .filter(vo -> Objects.nonNull(vo)
                && Objects.nonNull(vo.getValidationObject())
                && Objects.nonNull(vo.getValidationObject().getBase64()))
            .filter(vo -> Arrays
                .equals(md.digest(Base64.decode(vo.getValidationObject().getBase64())),
                    hashedValidationObject))
            .findFirst();
      } catch (NoSuchAlgorithmException e) {
        throw new ValidationObjectException("Internal error", ResultMajor.RESPONDER_ERROR,
            ResultMinor.GENERAL_ERROR);
      }
    }
  }


  public Optional<ValidationObjectType> findByHash(final byte[] hashedValidationObject,
      final String algo,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException {
    return this.findByHash(hashedValidationObject, algo, this.findAll(validationObjectListType));
  }

  /**
   * Find the Validation Object corresponding to the {@code uri} parameter in Validation Objects, if
   * it exists
   *
   * @param uri URI of the Validation Object
   * @param list list to go through
   * @return the Validation Objects corresponding to the {@code uri} parameter, or {@code
   * Optional.empty()}
   */
  private Optional<ValidationObjectType> findByUri(String uri,
      List<ValidationObjectType> list) {
    if (uri == null) {
      return Optional.empty();
    } else {
      Optional<ValidationObjectType> validationObject =
          list.stream()
              .filter(vo -> Objects.nonNull(vo)
                  && Objects.nonNull(vo.getValidationObject())
                  && Objects.nonNull(vo.getValidationObject().getURI()))
              .filter(vo -> vo.getValidationObject().getURI().equals(uri))
              .findFirst();
      return validationObject;
    }
  }

  /**
   * Find the Validation Object corresponding to the {@code object} parameter in Validation Objects,
   * if it exists
   *
   * @param object object to find as a "direct" object
   * @param list list to go through
   * @return the Validation Objects corresponding to the {@code object} parameter, or {@code
   * Optional.empty()}
   */
  private Optional<ValidationObjectType> findByDirect(Object object,
      List<ValidationObjectType> list) {
    if (object == null) {
      return Optional.empty();
    } else {
      Optional<ValidationObjectType> validationObject =
          list.stream()
              .filter(vo -> Objects.nonNull(vo)
                  && Objects.nonNull(vo.getValidationObject())
                  && Objects.nonNull(vo.getValidationObject().getURI()))
              .filter(vo -> vo.getValidationObject().getDirect().equals(object))
              .findFirst();
      return validationObject;
    }
  }
}
