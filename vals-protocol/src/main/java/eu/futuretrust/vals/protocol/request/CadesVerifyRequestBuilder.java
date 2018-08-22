package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.detection.TypeDetector;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.CadesUtils;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentType;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;
import eu.futuretrust.vals.protocol.helpers.InputDocumentsUtils;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CadesVerifyRequestBuilder extends VerifyRequestBuilder {

  private static final Logger LOGGER = LoggerFactory.getLogger(CadesVerifyRequestBuilder.class);

  /**
   * Instantiate by the following factory {@link VerifyRequestBuilderFactory}
   *
   * @param signature signature file to be validated
   */
  CadesVerifyRequestBuilder(byte[] signature) {
    super(signature);
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("New CadES Verify Request Builder");
    }
  }

  @Override
  public VerifyRequestType generate() throws SignatureException
  {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Generating new CadES Verify Request");
    }

    CMSSignedData signedData = CadesUtils.getSignedData(signature);
    SignedObjectType signatureType = TypeDetector.detect(signedData);

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("CadES Signature type: {}", signatureType.name());
    }

    setCommonDefaultAttributes();

    if (signatureType.isDetached()) {
      // Input Documents (for detached signature)
      setInputDocuments();
    }

    Base64DataType base64DataSignature = getBase64Data(SignatureFormat.CMS.getMimeTypes()[0]);
    setSignatureObject(base64DataSignature);

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("CadES Verify Request has been generated");
    }
    return this.getVerifyRequest();
  }

  @Override
  public SignatureFormat getSignatureFormat() {
    return SignatureFormat.CMS;
  }

  @Override
  public SignedObjectType getSignatureType() throws SignatureException {
    return TypeDetector.detect(CadesUtils.getSignedData(signature));
  }

  /**
   * set input documents
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

}
