package eu.futuretrust.vals.protocol.validation;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.exceptions.SignedObjectException;
import eu.futuretrust.vals.protocol.input.documents.HashedDocument;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.input.documents.InputDocumentHash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureValidation {

  private static final Logger LOGGER = LoggerFactory.getLogger(SignatureValidation.class);

  private byte[] signature;
  private byte[] policy;
  private List<InputDocument> documents;
  private List<InputDocumentHash> documentHashes;

  /**
   * @param signature a xml, cms or pdf signature
   * @param policy a signature validation policy
   */
  public SignatureValidation(byte[] signature, byte[] policy) {
    this(signature, policy, Collections.emptyList());
  }

  /**
   * @param signature a xml, cms or pdf signature
   * @param policy a signature validation policy
   * @param documents a map of external documents, between their URI and bytes
   */
  public SignatureValidation(byte[] signature, byte[] policy, List<InputDocument> documents) {
    if (documents == null) {
      throw new NullPointerException("documents must not be null");
    }
    this.signature = signature;
    this.policy = policy;
    this.documents = documents;
  }

  /**
   * @param signature a xml, cms or pdf signature
   * @param policy a signature validation policy
   * @param documents a map of external documents, between their URI and bytes
   */
  public SignatureValidation(byte[] signature, byte[] policy, List<InputDocument> documents,
                             List<InputDocumentHash> documentHashes) {
    if (documents == null) {
      throw new NullPointerException("documents must not be null");
    }
    this.signature = signature;
    this.policy = policy;
    this.documents = documents;
    this.documentHashes = documentHashes;
  }

  /**
   * Returns the Reports after validating in a standard manner the signature {@code signature} using
   * the policy {@code signaturePolicy} and the external documents {@code documents} all of this
   * using DSS and the global trust list.
   */
  public Reports validate(final CertificateVerifier certificateVerifier)
      throws SignedObjectException, InputDocumentException {
    if (signature == null) {
      throw new SignedObjectException("Signature is null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    if (documents == null) {
      throw new InputDocumentException("documents is null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    // Create DSS Document to verify
    DSSDocument signatureDSSDocument = new InMemoryDocument(signature);

    // Create the signature validator
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureDSSDocument);

    // Add the external documents
    List<DSSDocument> detachedList;
    if (!Utils.isCollectionEmpty(documentHashes)) {
      detachedList = documentHashes.stream()
          .map(inputDocumentHash -> {
            DigestDocument digestDocument = new DigestDocument();
            for (HashedDocument hashedDocument : inputDocumentHash.getHashedDocuments()) {
              digestDocument.addDigest(
                  DigestAlgorithm.forXML(hashedDocument.getHashingAlgorithm(), DigestAlgorithm.SHA256),
                  new String(hashedDocument.getHashedContent()));
            }
            return digestDocument;
          })
          .collect(Collectors.toList());
    } else {
      detachedList = documents.stream()
          .map(document -> new InMemoryDocument(document.getContent(), document.getName()))
          .collect(Collectors.toList());
    }

    validator.setDetachedContents(detachedList);

    validator.setCertificateVerifier(certificateVerifier);

    if (policy == null) {
      return validator.validateDocument();
    } else {
      ByteArrayInputStream policyInputStream = new ByteArrayInputStream(policy);
      return validator.validateDocument(policyInputStream);
    }
  }

}