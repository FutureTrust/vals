package eu.futuretrust.vals.web.services.report;


import eu.futuretrust.vals.core.manifest.exceptions.ManifestException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.exceptions.SignedObjectException;
import eu.futuretrust.vals.protocol.exceptions.VerifyResponseException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import java.util.List;

public interface ValidationReportBuilderService {

  ValidationReport generate(final VerifyRequestType verifyRequest, final SignedObject signedObject,
      final Policy policy, final List<InputDocument> inputDocuments, DSSResponseType responseType)
      throws VerifyResponseException, InputDocumentException, SignedObjectException, SignatureException, ManifestException;
}
