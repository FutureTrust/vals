package eu.futuretrust.vals.protocol.extractors;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentType;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import java.util.ArrayList;
import java.util.List;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

public class InputDocumentsExtractor {

  private VerifyRequestType verifyRequest;

  public InputDocumentsExtractor(VerifyRequestType verifyRequest) {
    this.verifyRequest = verifyRequest;
  }

  public List<InputDocument> extract() throws InputDocumentException {
    if (containsDocuments()) {
      return extractDocuments();
    }
    return new ArrayList<>();
  }

  private List<InputDocument> extractDocuments() throws InputDocumentException {
    List<InputDocument> inputDocuments = new ArrayList<>();
    for (DocumentType document : this.verifyRequest.getInputDocuments().getDocument()) {
      if (hasInvalidBase64(document)) {
        throw new InputDocumentException("The format of the input document is invalid",
            ResultMajor.REQUESTER_ERROR, ResultMinor.NOT_SUPPORTED);
      }

      String refURI = document.getRefURI();

      // check only one refURI omitted
      if (isEmpty(refURI) && containsEmptyName(inputDocuments)) {
        throw new InputDocumentException(
            "At least two input documents does not have a RefURI, only one RefURI can be omitted",
            ResultMajor.REQUESTER_ERROR,
            ResultMinor.MORE_THAN_ONE_REF_URI_OMITTED);
      }

      // check if two input documents have the same refURI
      if (containsName(inputDocuments, refURI)) {
        throw new InputDocumentException(
            "At least two input documents have the same RefURI, the RefURI should be unique for each input document",
            ResultMajor.REQUESTER_ERROR,
            ResultMinor.INVALID_REF_URI);
      }

      try {
        inputDocuments
            .add(new InputDocument(refURI, Base64.decode(document.getBase64Data().getValue())));
      } catch (Base64DecodingException e) {
        throw new InputDocumentException(
            "Unable to decode the base64 value of the input document (RefURI=" + refURI + ") : "
                + e.getMessage(), ResultMajor.REQUESTER_ERROR, ResultMinor.NOT_SUPPORTED);
      }
    }
    return inputDocuments;
  }

  private boolean containsEmptyName(List<InputDocument> list) {
    return list.stream().anyMatch(doc -> doc.getName() == null || "".equals(doc.getName()));
  }

  private boolean containsName(List<InputDocument> list, String name) {
    return list.stream().anyMatch(
        doc -> name == null && doc.getName() == null
            || doc.getName() != null && doc.getName().equals(name));
  }

  private boolean isEmpty(String str) {
    return str == null || str.isEmpty();
  }

  private boolean hasInvalidBase64(DocumentType document) {
    return document.getBase64Data() == null || document.getBase64Data().getValue() == null;
  }

  private boolean containsDocuments() {
    return this.verifyRequest != null && this.verifyRequest.getInputDocuments() != null
        && this.verifyRequest.getInputDocuments().getDocument() != null
        && !this.verifyRequest.getInputDocuments().getDocument().isEmpty();
  }

}
