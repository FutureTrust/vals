package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.detection.TypeDetector;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.XadesUtils;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentHashType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentType;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.helpers.InputDocumentsUtils;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import org.apache.commons.collections.CollectionUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class XadesVerifyRequestBuilder extends VerifyRequestBuilder {

  private static final Logger LOGGER = LoggerFactory.getLogger(XadesVerifyRequestBuilder.class);

  /**
   * Instantiate by the following factory {@link VerifyRequestBuilderFactory}
   *
   * @param signature signature file to be validated
   */
  XadesVerifyRequestBuilder(byte[] signature) {
    super(signature);
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("New XadES Verify Request Builder");
    }
  }

  @Override
  public VerifyRequestType generate() throws SignatureException
  {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Generating new XadES Verify Request");
    }

    Document document = XadesUtils.getDocument(signature);
    List<XMLSignature> xmlSignatures = XadesUtils.getXmlSignatures(document);

    if (xmlSignatures.isEmpty()) {
      throw new SignatureException("No signature found in the document");
    }

    // TODO: Ensure multiple signatures support
    XMLSignature xmlSignature = xmlSignatures.get(0);
    SignedObjectType signatureType = TypeDetector.detect(xmlSignature);

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("XadES Signature type: {}", signatureType.name());
    }

    setCommonDefaultAttributes();

    if (signatureType.isDetached()) {
      // Input Documents (for detached signature)
      setInputDocuments();
    }

    if (signatureType.isEnveloping()) {
      // Manifests (for enveloping signature)
      List<Manifest> manifests = XadesUtils.getManifests(document);
      if (CollectionUtils.isNotEmpty(manifests)) {
        setVerifyManifestsToTrue();
        if (!signatureType.isDetached()) {
          // if the signature is detached the input documents has already been set
          setInputDocuments();
        }
      }
    }

    Base64DataType base64DataSignature = getBase64Data(SignatureFormat.XML.getMimeTypes()[0]);
    if (signatureType.isEnveloped()) {
      // Document with signature (for enveloped signature)
      setDocumentWithSignature(base64DataSignature);
    } else {
      // Signature Object (for non-enveloped signature)
      setSignatureObject(base64DataSignature);
    }

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("XadES Verify Request has been generated");
    }
    return this.getVerifyRequest();
  }

  @Override
  public SignatureFormat getSignatureFormat() {
    return SignatureFormat.XML;
  }

  @Override
  public SignedObjectType getSignatureType() throws SignatureException {
    List<XMLSignature> xmlSignatures = XadesUtils.getXmlSignatures(signature);
    XMLSignature xmlSignature = xmlSignatures.get(0);
    return TypeDetector.detect(xmlSignature);
  }

  /**
   * set all documents as input documents
   */
  private void setInputDocuments() {
    if (CollectionUtils.isNotEmpty(documents)) {
      documents.forEach(this::addDocumentIntoInputDocuments);
    }
  }

  /**
   * Transform the document in byte array into a document of type {@link DocumentType}
   *
   * @param document document to be added into the input documents
   */
  private void addDocumentIntoInputDocuments(InputDocument document) {
    DocumentType documentType = InputDocumentsUtils.getInputDocument(document);
    addInputDocuments(documentType);
  }

  /**
   * THIS METHOD IS UNUSED BUT WE KEEP IT FOR FUTURE IMPROVEMENTS set input documents
   *
   * @param xmlSignature object representing a XadES signature
   * @throws InputDocumentException whenever the input document is missing for a reference
   * @throws SignatureException whenever the signature is null or contains an invalid SignedInfo
   * element
   */
  @SuppressWarnings("unused")
  private void setInputDocuments(XMLSignature xmlSignature)
      throws InputDocumentException, SignatureException {
    if (xmlSignature == null) {
      throw new SignatureException("XMLSignature cannot be null");
    }
    if (xmlSignature.getSignedInfo() == null || xmlSignature.getSignedInfo().getLength() == 0) {
      throw new SignatureException("Cannot find Signed info element");
    }

    int nbReferences = xmlSignature.getSignedInfo().getLength();
    for (int i = 0; i < nbReferences; i++) {
      Reference reference;

      try {
        reference = xmlSignature.getSignedInfo().item(i);
      } catch (XMLSecurityException e) {
        throw new SignatureException(
            "Reference at index " + i
                + " cannot be parsed (please check that the signature is well-formed) : " + e
                .getMessage());
      }

      if (XadesUtils.isReferenceDetached(reference)) {

        // Documents
        Optional<InputDocument> document = InputDocumentsUtils.findInputDocuments(reference, documents);
        if (document.isPresent()) {
          addDocumentIntoInputDocuments(reference, document.get());
        } else {
          /* THIS PART WILL NOT BE IMPLEMENTED BECAUSE DURING THE VERIFY REQUEST GENERATION THE USER
           * ONLY PROVIDES THE DOCUMENTS (NO TRANSFORMED DATA OR DOCUMENT HASH ALLOWED).
           *
           * The protocol defines Document, Transformed Data and Document Hash.
           * Only ONE of those three types SHOULD be used for ONE single document.
           * DocumentType or else Transformed Data or else Document Hash.
           */

          // Transformed Data

          // else {
          // Document hashes
          // boolean isReferenced = XadesUtils.findInputDocumentHashes(reference, documents);
          // if (isReferenced) {
          //   addDocumentIntoInputDocumentHashes(reference);
          // } else {
          //   String errorMessage = "Document is missing for the reference \"" + reference.getURI()
          //       + "\", please provide the detached document";
          //   LOGGER.error(errorMessage);
          //   throw new InputDocumentException(errorMessage);
          // }
          // }

          String errorMessage = "Document is missing for the reference \"" + reference.getURI()
              + "\", please provide the detached document";
          LOGGER.error(errorMessage);
          throw new InputDocumentException(errorMessage, ResultMajor.REQUESTER_ERROR, ResultMinor.REFERENCED_DOCUMENT_NOT_PRESENT);
        }
      }
    }
  }

  /**
   * THIS METHOD IS UNUSED BUT WE KEEP IT FOR FUTURE IMPROVEMENTS Add the documents referenced by
   * the manifests into the input documents
   */
  @SuppressWarnings("unused")
  private void setInputDocuments(List<Manifest> manifests) {
    manifests.forEach(manifest ->
        addDocumentIntoInputDocuments(InputDocumentsUtils.findInputDocuments(manifest, documents)));
  }

  /**
   * THIS METHOD IS UNUSED BUT WE KEEP IT FOR FUTURE IMPROVEMENTS Add the documents referenced by
   * the manifests into the input documents
   */
  @SuppressWarnings("unused")
  private void setInputDocumentHashes(List<Manifest> manifests) {
    manifests.forEach(manifest ->
        addDocumentIntoInputDocumentHashes(
            InputDocumentsUtils.findInputDocumentHashes(manifest, documents)));
  }

  /**
   * Add the documents referenced by the manifests into the input documents
   *
   * @param inputDocuments input documents to be added
   */
  private void addDocumentIntoInputDocuments(Map<Reference, InputDocument> inputDocuments) {
    if (inputDocuments != null && !inputDocuments.isEmpty()) {
      inputDocuments.forEach(this::addDocumentIntoInputDocuments);
    }
  }

  /**
   * Add a document into the input documents
   *
   * @param reference reference (URI) of the document
   * @param document byte array representing the document
   */
  private void addDocumentIntoInputDocuments(Reference reference, InputDocument document) {
    DocumentType documentType = InputDocumentsUtils.getInputDocument(reference, document);
    addInputDocuments(documentType);
  }

  /**
   * Add the documents referenced by the manifests into the input documents
   *
   * @param inputDocuments input documents to be added
   */
  private void addDocumentIntoInputDocumentHashes(Set<Reference> inputDocuments) {
    if (inputDocuments != null && !inputDocuments.isEmpty()) {
      inputDocuments.forEach(this::addDocumentIntoInputDocumentHashes);
    }
  }

  /**
   * Add a document into the input documents
   *
   * @param reference reference (URI) of the document
   */
  private void addDocumentIntoInputDocumentHashes(Reference reference) {
    try {
      DocumentHashType documentHashType = InputDocumentsUtils.getInputDocumentHash(reference);
      addInputDocuments(documentHashType);
    } catch (XMLSecurityException e) {
      // nothing
    }
  }

}
