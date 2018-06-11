package eu.futuretrust.vals.core.manifest;

import eu.futuretrust.vals.core.detection.TypeDetector;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.helpers.CryptoUtils;
import eu.futuretrust.vals.core.helpers.XmlUtils;
import eu.futuretrust.vals.core.helpers.exceptions.ReferenceException;
import eu.futuretrust.vals.core.manifest.exceptions.ManifestException;
import eu.futuretrust.vals.core.signature.XadesUtils;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections.CollectionUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class ManifestVerifier {

  public enum ValidationStatus {
    VALID,
    INVALID,
    DETACHED
  }

  private static final Logger LOGGER = LoggerFactory.getLogger(ManifestVerifier.class);

  private final byte[] signature;
  private final List<byte[]> documents;

  /**
   * @param signature signature file to be validated
   * @param inputDocuments external documents to be validated against the manifest
   */
  public ManifestVerifier(final byte[] signature, final List<byte[]> inputDocuments) {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("New Manifest Verifier");
    }

    if (signature == null) {
      throw new NullPointerException("Signature is null");
    } else {
      this.signature = signature;
    }

    if (inputDocuments == null) {
      this.documents = Collections.emptyList();
    } else {
      this.documents = inputDocuments;
    }
  }

  /**
   * @param signature signature file to be validated
   * @param document external document to be validated against the manifest
   */
  public ManifestVerifier(final byte[] signature, final byte[] document) {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("New Manifest Verifier");
    }
    this.signature = signature;
    this.documents = Collections.singletonList(document);
  }

  /**
   * verify if the documents are valid against the manifest
   *
   * @return true if all the documents (excluding documents from detached signature) are present in
   * the manifest
   * @throws ManifestException thrown whenever a manifest cannot be retrieved from the signature
   */
  public boolean verify() throws ManifestException, SignatureException {
    XMLSignature xmlSignature;
    // there should be only one signature
    xmlSignature = XadesUtils.getXmlSignatures(signature).get(0);

    // detect the type of signature
    SignedObjectType signatureType = TypeDetector.detect(xmlSignature);
    if (!signatureType.isEnveloping()) {
      throw new SignatureException("The signature is not enveloping");
    }

    List<Manifest> manifests = retrieveManifests();

    boolean result;
    if (signatureType.isDetached()) {
      // there are possibly some input documents that are part of the detached signature but not part of the manifest, so they need to be filtered
      result = documents.stream().allMatch(
          document -> isDetached(document, xmlSignature) || isReferenced(document, manifests));
    } else {
      // all input documents should be part of the manifest
      result = documents.stream().allMatch(document -> isReferenced(document, manifests));
    }
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Manifest validity: {}", result);
    }
    return result;
  }

  /**
   * verify if the documents are valid against the manifest and return the status of each document
   *
   * @return result for each input documents
   * @throws SignatureException thrown whenever a manifest cannot be retrieved from the signature
   */
  public Map<byte[], ValidationStatus> verifyAsMap() throws SignatureException, ManifestException {
    XMLSignature xmlSignature;
    // there should be only one signature
    xmlSignature = XadesUtils.getXmlSignatures(signature).get(0);

    // detect the type of signature
    SignedObjectType signatureType = TypeDetector.detect(xmlSignature);
    if (!signatureType.isEnveloping()) {
      throw new SignatureException("The signature is not enveloping");
    }

    List<Manifest> manifests = retrieveManifests();

    Map<byte[], ValidationStatus> map = new HashMap<>();
    for (byte[] document : documents) {
      ValidationStatus status;
      if (signatureType.isDetached() && isDetached(document, xmlSignature)) {
        status = ValidationStatus.DETACHED;
      } else if (isReferenced(document, manifests)) {
        status = ValidationStatus.VALID;
      } else {
        status = ValidationStatus.INVALID;
      }
      map.put(document, status);
    }
    return map;
  }

  /**
   * verify each reference of the manifests
   *
   * @return XPath of the reference and the resulting validation status of the reference
   * @throws SignatureException thrown whenever a manifest cannot be retrieved from the signature
   */
  public Map<String, Boolean> verifyReferences() throws SignatureException, ManifestException {
    List<Manifest> manifests = retrieveManifests();

    Map<String, Boolean> map = new HashMap<>();
    for (Manifest manifest : manifests) {
      int manifestLength = manifest.getLength();
      for (int i = 0; i < manifestLength; i++) {
        try {
          Reference reference = manifest.item(i);
          Element node = reference.getElement();
          String xPath = XmlUtils.getXPath(node);
          map.put(xPath, isReferenced(reference, documents));
        } catch (XMLSecurityException e) {
          // if Reference cannot be retrieved don't use it
          LOGGER.error("Reference n°{} cannot be retrieved: {}", i, e.getMessage());
        }
      }
    }
    return map;
  }

  private List<Manifest> retrieveManifests() throws SignatureException, ManifestException {
    // retrieve the DOM from the signature file
    Document signatureDoc = XadesUtils.getDocument(signature);

    // get the manifests
    List<Manifest> manifests = XadesUtils.getManifests(signatureDoc);
    if (CollectionUtils.isEmpty(manifests)) {
      throw new ManifestException("No manifest found");
    }
    return manifests;
  }

  /**
   * check if the document is referenced as a detached document
   *
   * @param document document to find in detached signature
   * @param xmlSignature detached signature
   * @return true if the document is referenced as a detached document in the signature
   */
  private static boolean isDetached(final byte[] document,
      final XMLSignature xmlSignature) {
    int signedInfoLength = xmlSignature.getSignedInfo().getLength();
    for (int i = 0; i < signedInfoLength; i++) {
      try {
        Reference reference = xmlSignature.getSignedInfo().item(i);
        if (isValid(document, reference)) {
          return true;
        }
      } catch (NoSuchAlgorithmException | IOException e) {
        LOGGER.error("Error while computing digest: {}", e.getMessage());
      } catch (XMLSecurityException | ReferenceException e) {
        LOGGER.error("Reference n°{} cannot be retrieved: {}", i, e.getMessage());
      }
    }
    return false;
  }

  /**
   * check if the document is referenced in the manifests
   *
   * @param document document to find in manifests
   * @param manifests list of manifests to be verified
   * @return true if the document is referenced in one of the manifests
   */
  private static boolean isReferenced(byte[] document, final List<Manifest> manifests) {
    if (manifests == null || CollectionUtils.isEmpty(manifests)) {
      // no manifest found or no document, the manifest verification is useless
      return true;
    }

    for (Manifest manifest : manifests) {
      if (isReferenced(document, manifest)) {
        return true;
      }
    }
    return false;
  }

  /**
   * check if the document is referenced in the manifest
   *
   * @param document document to find in manifests
   * @param manifest manifest to be verified
   * @return true if the document is referenced in the manifest
   */
  private static boolean isReferenced(final byte[] document, final Manifest manifest) {
    if (manifest == null || manifest.getLength() == 0) {
      // no manifest found or no document, the manifest verification is useless
      return true;
    }

    int manifestElementLength = manifest.getLength();
    for (int i = 0; i < manifestElementLength; i++) {
      try {
        Reference reference = manifest.item(i);
        if (isValid(document, reference)) {
          return true;
        }
      } catch (NoSuchAlgorithmException | IOException e) {
        LOGGER.error("Error while computing digest: {}", e.getMessage());
      } catch (XMLSecurityException | ReferenceException e) {
        LOGGER.error("Reference n°{} cannot be retrieved: {}", i, e.getMessage());
      }
    }
    return false;
  }

  /**
   * check if the reference matches one of the documents
   *
   * @param reference reference to be verified
   * @param documents documents to match against the reference
   * @return true if one of the documents matches the reference
   */
  private static boolean isReferenced(final Reference reference,
      final List<byte[]> documents) {
    if (documents == null || CollectionUtils.isEmpty(documents) || reference == null) {
      // if there is no documents or reference is null, the reference is considered as INVALID
      return false;
    }

    for (byte[] document : documents) {
      try {
        if (isValid(document, reference)) {
          return true;
        }
      } catch (NoSuchAlgorithmException | IOException e) {
        LOGGER.error("Error while computing digest: {}", e.getMessage());
      } catch (XMLSecurityException | ReferenceException e) {
        LOGGER.error("Reference cannot be retrieved: {}", e.getMessage());
      }
    }
    return false;
  }

  /**
   * check if the document matches the reference
   *
   * @param document document to be matched against the reference
   * @param reference reference to be matched against the document
   * @return true if the digest value of the reference is equals to the digest computed from the
   * document
   * @throws XMLSecurityException whenever the document transformation failed or the reference is
   * invalid
   * @throws IOException whenever the document cannot be read
   * @throws NoSuchAlgorithmException whenever the digest algorithm is invalid
   */
  private static boolean isValid(final byte[] document, final Reference reference)
      throws XMLSecurityException, ReferenceException, NoSuchAlgorithmException, IOException {
    XMLSignatureInput currentDocument = CryptoUtils.transform(reference, document);
    byte[] expectedResult = CryptoUtils.computeDigest(reference, currentDocument);
    return CryptoUtils.equals(expectedResult, reference.getDigestValue());

  }

}
