package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.futuretrust.vals.common.exceptions.VerifyRequestException;
import eu.futuretrust.vals.core.ers.rfc4998.CMSERSDSSValidator;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ResultType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import eu.futuretrust.vals.protocol.utils.VerifyResponseUtils;
import eu.futuretrust.vals.web.services.report.ValidationReportBuilderService;
import org.bouncycastle.cms.EvidenceRecordVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ERSValidationReportBuilderService implements ValidationReportBuilderService {

  @Override
  public ValidationReport generate(VerifyRequestType verifyRequest, SignedObject signedObject,
                                   Policy policy, List<InputDocument> inputDocuments, DSSResponseType responseType) {
    EvidenceRecordVerifier evidenceRecordVerifier = new EvidenceRecordVerifier(BouncyCastleProvider.PROVIDER_NAME);
    CMSERSDSSValidator cmsersdssValidator = new CMSERSDSSValidator(new CommonCertificateVerifier(), evidenceRecordVerifier);
    VerifyResponseType verifyResponseType;
    try {
      verifyResponseType = cmsersdssValidator.validate(verifyRequest);
    } catch (VerifyRequestException e) {
        ResultType result = ObjectFactoryUtils.FACTORY_OASIS_CORE_2.createResultType();
        result.setResultMajor(e.getResultMajor().getURI());
        result.setResultMinor(e.getResultMinor().getURI());
        result.setResultMessage(VerifyResponseUtils.getResultMessage(e.getMessage()));
        return new ValidationReport(result);
    }
    return new ValidationReport(verifyResponseType.getResult());
  }
}
