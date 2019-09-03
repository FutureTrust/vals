package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureIdentifierType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureQualityType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureValidationProcessType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignatureValidationReportType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.SignerInformationType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.VOReferenceType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationReportData;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationStatusType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.enums.SignatureValidationProcessID;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.protocol.exceptions.MessageDigestException;
import eu.futuretrust.vals.protocol.exceptions.ValidationObjectException;
import eu.futuretrust.vals.protocol.exceptions.ValidationReportDataException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import eu.futuretrust.vals.web.services.report.IndividualReportBuilderService;
import eu.futuretrust.vals.web.services.report.SignatureValidationReportBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationObjectsBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationReportDataBuilderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class SignatureValidationReportBuilderServiceImpl implements SignatureValidationReportBuilderService {

    private final static Logger LOGGER = LoggerFactory.getLogger(SignatureValidationReportBuilderServiceImpl.class);
    private ValidationReportDataBuilderService validationReportDataBuilderService;
    private IndividualReportBuilderService individualReportBuilderService;
    private ValidationObjectsBuilderService validationObjectsBuilderService;

    @Autowired
    public SignatureValidationReportBuilderServiceImpl(ValidationReportDataBuilderService validationReportDataBuilderService,
                                                       IndividualReportBuilderService individualReportBuilderService,
                                                       ValidationObjectsBuilderService validationObjectsBuilderService) {
        this.validationReportDataBuilderService = validationReportDataBuilderService;
        this.individualReportBuilderService = individualReportBuilderService;
        this.validationObjectsBuilderService = validationObjectsBuilderService;
    }

    @Override
    public SignatureValidationReportType generateSignatureValidationReportType(
        VerifyRequestType verifyRequest,
        SignatureWrapper signatureWrapper,
        SignedObject signedObject,
        Policy policy,
        Reports reports,
        DiagnosticData diagnosticData,
        SimpleReport simpleReport,
        ValidationObjectListType validationObjectListType,
        MainIndication mainIndication,
        SubIndication subIndication) {
        SignatureValidationReportType signatureValidationReport = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createSignatureValidationReportType();
        signatureValidationReport.setSignatureIdentifier(generateSignatureIdentifierAttributes(signatureWrapper, signedObject, verifyRequest));
        signatureValidationReport.setSignerInformation(generateSignerInformation(signatureWrapper, reports, validationObjectListType));
        signatureValidationReport.setValidationStatus(generateValidationStatus(signatureWrapper,
            policy, diagnosticData, simpleReport, validationObjectListType, mainIndication, subIndication));
        signatureValidationReport.setSignatureQuality(generateSignatureQualityInformation(reports, signatureWrapper));
        signatureValidationReport.setSignatureValidationProcessType(generateSignatureValidationProcessInformation());
        return signatureValidationReport;
    }

    private ValidationStatusType generateValidationStatus(
        SignatureWrapper signatureWrapper,
        Policy policy,
        DiagnosticData diagnosticData,
        SimpleReport simpleReport,
        ValidationObjectListType validationObjectListType,
        MainIndication mainIndication,
        SubIndication subIndication) {
        ValidationStatusType validationStatus = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createValidationStatusType();
        validationStatus.setMainIndication(mainIndication.getURI());
        if (subIndication != null && subIndication.getURI() != null) {
            validationStatus.setSubIndication(subIndication.getURI());
        }

        try {
            ValidationReportData validationReportData = validationReportDataBuilderService.generate(
                signatureWrapper,
                policy,
                diagnosticData,
                simpleReport,
                mainIndication,
                subIndication,
                validationObjectListType
            );
            validationStatus.getAssociatedValidationReportData().add(validationReportData.getValue());
        } catch (ValidationObjectException | ValidationReportDataException e) {
            LOGGER.error("Validation report data generation failed %s", e);
        }
        return validationStatus;
    }

    // SignatureIdentifier
    private SignatureIdentifierType generateSignatureIdentifierAttributes(
        SignatureWrapper signatureWrapper, SignedObject signedObject, VerifyRequestType verifyRequest) {
        SignatureIdentifierType signatureIdentifier = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createSignatureIdentifierType();
        signatureIdentifier.setId(signatureWrapper.getId());
        try {
            signatureIdentifier.setDigestAlgAndValue(individualReportBuilderService.createDigestAlgAndValue(signedObject.getContent()));
        } catch (MessageDigestException e) {
            LOGGER.error("Create digest algorithm value failed: %s", e);
        }
        // HashOnly & DocHashOnly
        if (verifyRequest.getInputDocuments() != null
            && verifyRequest.getInputDocuments().getDocument() != null
            && !verifyRequest.getInputDocuments().getDocument().isEmpty()
            && verifyRequest.getInputDocuments().getDocumentHash() != null
            && !verifyRequest.getInputDocuments().getDocumentHash().isEmpty()) {
            signatureIdentifier.setHashOnly(false);
            signatureIdentifier.setDocHashOnly(false);
        } else if (signedObject.getType().isDetached()) {
            signatureIdentifier.setHashOnly(true);
            signatureIdentifier.setDocHashOnly(true);
        } else {
            signatureIdentifier.setHashOnly(false);
            signatureIdentifier.setDocHashOnly(false);
        }

        return signatureIdentifier;
    }

    private SignerInformationType generateSignerInformation(SignatureWrapper signatureWrapper,
                                                            Reports reports,
                                                            ValidationObjectListType validationObjectListType) {
        SignerInformationType signerInformationType = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createSignerInformationType();
        signerInformationType.setSigner(reports.getSimpleReport().getSignedBy(signatureWrapper.getId()));

        CertificateWrapper certificateWrapper = reports.getDiagnosticData()
            .getUsedCertificateById(signatureWrapper.getSigningCertificateId());
        DSSCertificateWrapperParser dssCertificateWrapperParser = new DSSCertificateWrapperParser();
        try {
            XmlCertificate xmlCertificate = dssCertificateWrapperParser.getXmlCertificateField(certificateWrapper);
            byte[] certToBase64 = dssCertificateWrapperParser.getCertificateBase64(certificateWrapper);
            Optional<ValidationObjectType> validationObjectTypeOptional = validationObjectsBuilderService.findByBase64(certToBase64, ValidationObjectTypeId.CERTIFICATE, validationObjectListType);
            VOReferenceType voReferenceToCertificateObject = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createVOReferenceType();
            voReferenceToCertificateObject.getVOReference().add(validationObjectTypeOptional.orElse(null));
            signerInformationType.setSignerCertificate(voReferenceToCertificateObject);
            signerInformationType.setPseudonym(xmlCertificate.getPseudonym() != null);
        } catch (DSSParserException e) {
            LOGGER.error("Finding VoReference to certificate object failed: %s", e);
        }
        return signerInformationType;
    }

    private SignatureQualityType generateSignatureQualityInformation(Reports reports, SignatureWrapper signatureWrapper) {
        SignatureQualityType signatureQuality = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createSignatureQualityType();
        String signatureQualityInformation = reports.getSimpleReport().getSignatureQualification(signatureWrapper.getId()).getLabel();
        signatureQuality.setSignatureQualityInformation(signatureQualityInformation);
        return signatureQuality;
    }

    private SignatureValidationProcessType generateSignatureValidationProcessInformation() {
        SignatureValidationProcessType signatureValidationProcess = ObjectFactoryUtils.FACTORY_ETSI_119_102_2.createSignatureValidationProcessType();
        signatureValidationProcess.setSignatureValidationProcessID(
            SignatureValidationProcessID.LTA.getURI());
        return signatureValidationProcess;
    }
}
