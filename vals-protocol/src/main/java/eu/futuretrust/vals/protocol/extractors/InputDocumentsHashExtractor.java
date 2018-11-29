package eu.futuretrust.vals.protocol.extractors;

import eu.europa.esig.dss.utils.Utils;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DigestInfoType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentHashType;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.input.documents.HashedDocument;
import eu.futuretrust.vals.protocol.input.documents.InputDocumentHash;

import java.util.ArrayList;
import java.util.List;

public class InputDocumentsHashExtractor
{

  private VerifyRequestType verifyRequest;

  public InputDocumentsHashExtractor(VerifyRequestType verifyRequest) {
    this.verifyRequest = verifyRequest;
  }

  public List<InputDocumentHash> extract() throws InputDocumentException {
    if (containsDocuments()) {
      return extractDocuments();
    }
    return new ArrayList<>();
  }

  private List<InputDocumentHash> extractDocuments() throws InputDocumentException {
    List<InputDocumentHash> inputDocumentHashList = new ArrayList<>();

    for (DocumentHashType documentHashType : this.verifyRequest.getInputDocuments().getDocumentHash()) {
      if (hasInvalidDigest(documentHashType)) {
        throw new InputDocumentException("The format of the input document is invalid",
            ResultMajor.REQUESTER_ERROR, ResultMinor.NOT_SUPPORTED);
      }

      String refURI = documentHashType.getRefURI();

      // check only one refURI omitted
      if (Utils.isStringEmpty(refURI) && containsEmptyName(inputDocumentHashList)) {
        throw new InputDocumentException(
            "At least two input documents does not have a RefURI, only one RefURI can be omitted",
            ResultMajor.REQUESTER_ERROR,
            ResultMinor.MORE_THAN_ONE_REF_URI_OMITTED);
      }

      // check if two input documents have the same refURI
      if (containsName(inputDocumentHashList, refURI)) {
        throw new InputDocumentException(
            "At least two input documents have the same RefURI, the RefURI should be unique for each input document",
            ResultMajor.REQUESTER_ERROR,
            ResultMinor.INVALID_REF_URI);
      }

      final List<HashedDocument> hashedDocuments = new ArrayList<>();
      documentHashType.getDigestInfos().forEach(digestInfoType ->
          hashedDocuments.add(new HashedDocument(digestInfoType.getDigestMethod(),
              digestInfoType.getDigestValue())));
      inputDocumentHashList.add(new InputDocumentHash(refURI, hashedDocuments));
    }
    return inputDocumentHashList;
  }

  private boolean hasInvalidDigest(DocumentHashType documentHashType) {
    if (Utils.isCollectionEmpty(documentHashType.getDigestInfos())) {
      return true;
    }
    for (DigestInfoType digestInfoType : documentHashType.getDigestInfos()) {
      if (Utils.isStringEmpty(digestInfoType.getDigestMethod()) ||
          Utils.isArrayEmpty(digestInfoType.getDigestValue())) {
        return true;
      }
    }
    return false;
  }

  private boolean containsName(List<InputDocumentHash> list, String name) {
    return list.stream().anyMatch(
        doc -> name == null && doc.getName() == null
            || doc.getName() != null && doc.getName().equals(name));
  }

  private boolean containsDocuments() {
    return this.verifyRequest != null && this.verifyRequest.getInputDocuments() != null
        && this.verifyRequest.getInputDocuments().getDocumentHash() != null
        && !this.verifyRequest.getInputDocuments().getDocumentHash().isEmpty();
  }

  private boolean containsEmptyName(List<InputDocumentHash> list) {
    return list.stream().anyMatch(doc -> doc.getName() == null || "".equals(doc.getName()));
  }
}
