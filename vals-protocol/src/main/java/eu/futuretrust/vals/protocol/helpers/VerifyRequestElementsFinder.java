package eu.futuretrust.vals.protocol.helpers;


import eu.futuretrust.vals.core.signature.exceptions.FormatException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import eu.futuretrust.vals.protocol.exceptions.SignedObjectNotFoundException;
import eu.futuretrust.vals.protocol.extractors.InputDocumentsExtractor;
import eu.futuretrust.vals.protocol.extractors.InputDoucmentsHashExtractor;
import eu.futuretrust.vals.protocol.extractors.PolicyExtractor;
import eu.futuretrust.vals.protocol.extractors.SignedObjectExtractor;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.input.documents.InputDocumentHash;

import java.util.List;
import java.util.Optional;

public final class VerifyRequestElementsFinder {

  private VerifyRequestElementsFinder() {
  }

  public static SignedObject findSignature(VerifyRequestType verifyRequest)
      throws SignedObjectNotFoundException, FormatException, ProfileNotFoundException, SignatureException {
    SignedObjectExtractor extractor = new SignedObjectExtractor();
    return extractor.extract(verifyRequest);
  }

  public static List<InputDocument> findInputDocuments(VerifyRequestType verifyRequest)
      throws InputDocumentException {
    InputDocumentsExtractor extractor = new InputDocumentsExtractor(verifyRequest);
    return extractor.extract();
  }

  public static List<InputDocumentHash> findInputDocumentHashes(VerifyRequestType verifyRequesttype)
  throws InputDocumentException {
    InputDoucmentsHashExtractor extractor = new InputDoucmentsHashExtractor(verifyRequesttype);
    return extractor.extract();
  }

  public static Optional<Policy> findPolicy(VerifyRequestType verifyRequest) {
    PolicyExtractor extractor = new PolicyExtractor(verifyRequest);
    return extractor.extract();
  }

}
