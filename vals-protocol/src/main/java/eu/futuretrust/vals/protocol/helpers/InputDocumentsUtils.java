package eu.futuretrust.vals.protocol.helpers;

import eu.futuretrust.vals.core.helpers.CryptoUtils;
import eu.futuretrust.vals.core.helpers.exceptions.ReferenceException;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DigestInfoType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentHashType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentType;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.collections.CollectionUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.bouncycastle.util.encoders.Base64;

public final class InputDocumentsUtils {

  private InputDocumentsUtils() {
  }

  public static Optional<InputDocument> findInputDocuments(Reference reference,
      Set<InputDocument> documents) {
    if (reference == null || CollectionUtils.isEmpty(documents)) {
      return Optional.empty();
    }

    for (InputDocument document : documents) {
      try {
        XMLSignatureInput currentDocument = CryptoUtils.transform(reference, document.getContent());
        byte[] expectedResult = CryptoUtils.computeDigest(reference, currentDocument);
        if (Arrays.equals(expectedResult, reference.getDigestValue())) {
          return Optional.of(document);
        }
      } catch (XMLSecurityException | IOException | NoSuchAlgorithmException | ReferenceException ignored) {
        // if an exception is thrown, we assume that the document does not match the reference, so we ignore it and try with the next document
      }
    }
    return Optional.empty();
  }

  public static Map<Reference, InputDocument> findInputDocuments(Manifest manifest,
      Set<InputDocument> documents) {
    if (manifest == null || manifest.getLength() == 0 || CollectionUtils.isEmpty(documents)) {
      return Collections.emptyMap();
    }

    Map<Reference, InputDocument> map = new HashMap<>();
    int manifestElementLength = manifest.getLength();
    for (int i = 0; i < manifestElementLength; i++) {
      try {
        Reference reference = manifest.item(i);
        Optional<InputDocument> document = findInputDocuments(reference, documents);
        document.ifPresent(bytes -> map.put(reference, bytes));
      } catch (XMLSecurityException ignored) {
        // if Reference cannot be parsed just don't use it
      }
    }

    return map;
  }

  public static DocumentType getInputDocument(Reference reference, InputDocument document) {
    DocumentType documentType = getInputDocument(document);
    documentType.setRefType(reference.getType());
    documentType.setID(reference.getId());
    return documentType;
  }

  public static DocumentType getInputDocument(InputDocument document) {
    Base64DataType base64data = new Base64DataType();
    base64data.setValue(Base64.encode(document.getContent()));

    DocumentType documentType = new DocumentType();
    documentType.setRefURI(document.getName());
    documentType.setBase64Data(base64data);
    return documentType;
  }

  public static boolean findInputDocumentHashes(Reference reference,
      Set<InputDocument> documents) {
    if (reference == null || CollectionUtils.isEmpty(documents)) {
      return false;
    }

    for (InputDocument document : documents) {
      try {
        XMLSignatureInput currentDocument = CryptoUtils.transform(reference, document.getContent());
        byte[] expectedResult = CryptoUtils.computeDigest(reference, currentDocument);
        if (Arrays.equals(expectedResult, reference.getDigestValue())) {
          return true;
        }
      } catch (XMLSecurityException | IOException | NoSuchAlgorithmException | ReferenceException ignored) {
        // if an exception is thrown, we assume that the document does not match the reference, so we ignore it and try with the next document
      }
    }
    return false;
  }

  public static Set<Reference> findInputDocumentHashes(Manifest manifest,
      Set<InputDocument> documents) {
    if (manifest == null || manifest.getLength() == 0 || CollectionUtils.isEmpty(documents)) {
      return Collections.emptySet();
    }

    Set<Reference> list = new HashSet<>();
    int manifestElementLength = manifest.getLength();
    for (int i = 0; i < manifestElementLength; i++) {
      try {
        Reference reference = manifest.item(i);
        if (findInputDocumentHashes(reference, documents)) {
          list.add(reference);
        }
      } catch (XMLSecurityException ignored) {
        // if Reference cannot be parsed just don't use it
      }
    }

    return list;
  }

  public static DocumentHashType getInputDocumentHash(Reference reference)
      throws XMLSecurityException {
    DocumentHashType documentHashType = new DocumentHashType();
    documentHashType.setRefURI(reference.getURI());
    documentHashType.setRefType(reference.getType());
    documentHashType.setID(reference.getId());

    // transforms are not needed for validation

    DigestInfoType digestInfoType = new DigestInfoType();
    digestInfoType.setDigestMethod(reference.getMessageDigestAlgorithm().getJCEAlgorithmString());
    digestInfoType.setDigestValue(Base64.encode(reference.getDigestValue()));
    documentHashType.getDigestInfos().add(digestInfoType);

    return documentHashType;
  }

}
