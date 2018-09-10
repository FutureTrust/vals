package eu.futuretrust.vals.web.services.response.impl;

import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.manifest.exceptions.ManifestException;
import eu.futuretrust.vals.core.signature.exceptions.FormatException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.exceptions.PolicyException;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import eu.futuretrust.vals.protocol.exceptions.SignedObjectException;
import eu.futuretrust.vals.protocol.exceptions.VerifyRequestException;
import eu.futuretrust.vals.protocol.exceptions.VerifyResponseException;
import eu.futuretrust.vals.protocol.helpers.VerifyRequestElementsFinder;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import eu.futuretrust.vals.protocol.utils.ProfileUtils;
import eu.futuretrust.vals.protocol.utils.VerifyResponseUtils;
import eu.futuretrust.vals.web.services.report.impl.DSSValidationReportBuilderService;
import eu.futuretrust.vals.web.services.report.impl.ERSValidationReportBuilderService;
import eu.futuretrust.vals.web.services.report.impl.X509ValidationReportBuilderServiceImpl;
import eu.futuretrust.vals.web.services.response.VerifyResponseBuilderService;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class DSSVerifyResponseBuilderService implements VerifyResponseBuilderService {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(DSSVerifyResponseBuilderService.class);

  private DSSValidationReportBuilderService dssValidationReportBuilderService;
  private X509ValidationReportBuilderServiceImpl x509ValidationReportBuilderServiceImpl;
  private ERSValidationReportBuilderService ersValidationReportBuilderService;

  @Autowired
  public DSSVerifyResponseBuilderService(
      DSSValidationReportBuilderService dssValidationReportBuilderService,
      X509ValidationReportBuilderServiceImpl x509ValidationReportBuilderServiceImpl,
      ERSValidationReportBuilderService ersValidationReportBuilderService) {
    this.dssValidationReportBuilderService = dssValidationReportBuilderService;
    this.x509ValidationReportBuilderServiceImpl = x509ValidationReportBuilderServiceImpl;
    this.ersValidationReportBuilderService = ersValidationReportBuilderService;
  }

  @Override
  public VerifyResponseType generate(final VerifyRequestType verifyRequest,
      final Policy defaultPolicy, DSSResponseType responseType)
      throws VerifyRequestException, PolicyException, ProfileNotFoundException {
    if (verifyRequest == null) {
      throw new VerifyRequestException("VerifyRequest cannot be null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    Profile mainProfile = ProfileUtils.getMainProfile(verifyRequest);
    List<Profile> subProfiles = ProfileUtils.getSubProfiles(verifyRequest);

    final Policy policy = VerifyRequestElementsFinder.findPolicy(verifyRequest)
        .orElse(defaultPolicy);
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Policy loaded at URL {}", policy.getUrl());
    }
    if (isNotValidPolicy(policy)) {
      throw new PolicyException("No valid policy found", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    ValidationReport report;

    try {
      final SignedObject signedObject = VerifyRequestElementsFinder.findSignature(verifyRequest);
      final List<InputDocument> inputDocuments = VerifyRequestElementsFinder
              .findInputDocuments(verifyRequest);

      switch (signedObject.getType()) {
        case ENVELOPED:
        case ENVELOPED_DETACHED:
        case ENVELOPED_ENVELOPING_DETACHED:
        case DETACHED:
        case ENVELOPING:
        case ENVELOPING_DETACHED:
          report = dssValidationReportBuilderService
                  .generate(verifyRequest, signedObject, policy, inputDocuments, responseType);
          return generateVerifyResponse(report, verifyRequest, mainProfile, subProfiles);
        case CERTIFICATE:
          report = x509ValidationReportBuilderServiceImpl
                  .generate(verifyRequest, signedObject, policy, null, responseType);
          return generateVerifyResponse(report, verifyRequest, mainProfile, subProfiles);
        case EVIDENCE_RECORD:
          report = ersValidationReportBuilderService
              .generate(verifyRequest, signedObject, policy, inputDocuments, responseType);
          return generateVerifyResponse(report, verifyRequest, mainProfile, subProfiles);
      }
    } catch (SignedObjectException | InputDocumentException | VerifyResponseException e) {
      return VerifyResponseUtils
          .getVerifyResponse(e.getResultMajor(), e.getResultMinor(), e.getMessage(), verifyRequest);
    } catch (SignatureException | ManifestException | FormatException e) {
      return VerifyResponseUtils
          .getVerifyResponse(ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR, e.getMessage(),
              verifyRequest);
    }

    return null; //should throw an exception
  }

  private VerifyResponseType generateVerifyResponse(final ValidationReport report,
                                                    final VerifyRequestType verifyRequest,
                                                    final Profile mainProfile,
                                                    final List<Profile> subProfiles) {

    VerifyResponseType verifyResponse = VerifyResponseUtils
            .getVerifyResponse(report.getResult().getResultMajor(), report.getResult().getResultMinor(),
                    null, verifyRequest);
    verifyResponse.setOptionalOutputs(report.getOptionalOutputs());
    verifyResponse.getAppliedProfile().add(mainProfile.getUri());
    verifyResponse.getAppliedProfile()
            .addAll(subProfiles.stream().map(Profile::getUri).collect(Collectors.toList()));
    return verifyResponse;
  }

  private boolean isNotValidPolicy(Policy defaultPolicy) {
    return defaultPolicy == null
        || defaultPolicy.getContent() == null
        || defaultPolicy.getContent().length == 0
        || StringUtils.isEmpty(defaultPolicy.getUrl());
  }

}