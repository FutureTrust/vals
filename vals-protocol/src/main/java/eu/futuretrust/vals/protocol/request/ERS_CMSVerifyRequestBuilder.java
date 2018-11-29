package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.enums.ERSSignatureType;
import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentType;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;
import eu.futuretrust.vals.protocol.helpers.InputDocumentsUtils;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import org.apache.commons.collections.CollectionUtils;

import java.security.SecureRandom;

public class ERS_CMSVerifyRequestBuilder extends VerifyRequestBuilder {

  ERS_CMSVerifyRequestBuilder(byte[] certificate) {
    super(certificate);
  }

  @Override
  public VerifyRequestType generate() throws SignatureException {
    setRequestID();
    getVerifyRequest().getProfile().add(Profile.ERS.getUri());
    Base64DataType base64DataSignature = getBase64Data(SignedObjectFormat.ERS_CMS.getMimeTypes()[0]);
    setSignatureObject(base64DataSignature);
    setInputDocuments();
    setERSSignatureType(ERSSignatureType.RFC4998.getUrn());
    return getVerifyRequest();
  }

  @Override
  public SignatureFormat getSignatureFormat() {
    return null;
  }

  @Override
  public SignedObjectType getSignatureType() throws SignatureException {
    return null;
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
    documentType.setID(Integer.toString(new SecureRandom().nextInt(Integer.MAX_VALUE)));
    addInputDocuments(documentType);
  }
}

