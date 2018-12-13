package eu.futuretrust.vals.web.services.report;

import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureValidationReportType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.protocol.exceptions.VerifyResponseException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;

public interface SignatureValidationReportBuilderService {

    SignatureValidationReportType generateSignatureValidationReportType(
        VerifyRequestType verifyRequest,
        SignatureWrapper signatureWrapper,
        SignedObject signedObject,
        Policy policy,
        Reports reports,
        DiagnosticData diagnosticData,
        SimpleReport simpleReport,
        ValidationObjectListType validationObjectListType,
        MainIndication mainIndication,
        SubIndication subIndication) throws VerifyResponseException;
}
