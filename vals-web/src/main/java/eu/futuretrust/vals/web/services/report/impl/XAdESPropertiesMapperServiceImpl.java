package eu.futuretrust.vals.web.services.report.impl;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.ArchiveTimeStamp;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.AttrAuthoritiesCertValues;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.AttributeCertificateRefs;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.AttributeRevocationRefs;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.AttributeRevocationValues;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CRLValuesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CertificateValues;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CertifiedRolesListType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CompleteCertificateRefs;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CompleteRevocationRefs;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CounterSignature;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.EncapsulatedPKIDataType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.OCSPValuesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.RefsOnlyTimeStamp;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.RevocationValues;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.RevocationValuesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SigAndRefsTimeStamp;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignedDataObjectPropertiesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignedPropertiesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignedSignaturePropertiesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignerRoleType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.UnsignedPropertiesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.UnsignedSignaturePropertiesType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.XAdESTimeStampType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.AttrCertIDType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.AttributeCertificateContentType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.AttributeCertificateValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificatePathValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.EntityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.TimeStampValidityType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.web.services.report.ValidationObjectsBuilderService;
import eu.futuretrust.vals.web.services.report.XAdESPropertiesMapperService;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.xml.bind.JAXBElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class XAdESPropertiesMapperServiceImpl implements XAdESPropertiesMapperService {

  private ValidationObjectsBuilderService validationObjectsBuilderService;

  @Autowired
  public XAdESPropertiesMapperServiceImpl(
      ValidationObjectsBuilderService validationObjectsBuilderService) {
    this.validationObjectsBuilderService = validationObjectsBuilderService;
  }

  @Override
  public eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.UnsignedPropertiesType mapUnsignedProperties(
      UnsignedPropertiesType unsignedPropertiesTypeXADES,
      ValidationObjectListType validationObjectListType) throws DSSParserException {
    if (unsignedPropertiesTypeXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.UnsignedPropertiesType unsignedPropertiesTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createUnsignedPropertiesType();
    unsignedPropertiesTypeMULTI.setUnsignedSignatureProperties(mapUnsignedSignatureProperties(
        unsignedPropertiesTypeXADES.getUnsignedSignatureProperties(), validationObjectListType));
    return unsignedPropertiesTypeMULTI;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.UnsignedSignaturePropertiesType mapUnsignedSignatureProperties(
      UnsignedSignaturePropertiesType unsignedSignaturePropertiesTypeXADES,
      ValidationObjectListType validationObjectListType)
      throws DSSParserException {
    if (unsignedSignaturePropertiesTypeXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.UnsignedSignaturePropertiesType unsignedSignaturePropertiesTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createUnsignedSignaturePropertiesType();
    List<JAXBElement<?>> thingsList = unsignedSignaturePropertiesTypeMULTI
        .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs();

    for (Object o : unsignedSignaturePropertiesTypeXADES
        .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()) {
      int originalSize = thingsList.size();
      boolean ignoreSizeComparison = false;

      if (o.getClass().equals(ArchiveTimeStamp.class)) {
        ArchiveTimeStamp archiveTimeStamp = (ArchiveTimeStamp) o;
        // TODO: mapTimestampValidity need to be fixed
        /*thingsList.add(ObjectFactoryUtils.FACTORY_OASIS_DSSX
            .createUnsignedSignaturePropertiesTypeArchiveTimeStamp(
                mapTimestampValidity(archiveTimeStamp.getValue(), validationObjectListType)
            ));*/
      }
      // TODO: timestamp does not work because no base64 value
      /*
      if (o.getClass().equals(SignatureTimeStamp.class)) {
        SignatureTimeStamp signatureTimeStamp = (SignatureTimeStamp) o;
        // TODO: mapTimestampValidity need to be fixed
        thingsList.add(ObjectFactoryUtils.FACTORY_OASIS_DSSX
            .createUnsignedSignaturePropertiesTypeSignatureTimeStamp(
                mapTimestampValidity(signatureTimeStamp.getValue(), validationObjectListType)));

      }
      */
      if (o.getClass().equals(RevocationValues.class)) {
        RevocationValues revocationValues = (RevocationValues) o;
        thingsList.add(ObjectFactoryUtils.FACTORY_OASIS_DSSX
            .createUnsignedSignaturePropertiesTypeRevocationValues(
                mapRevocationValues(revocationValues.getValue(), validationObjectListType)));
      }
      if (o.getClass().equals(AttributeCertificateRefs.class)) {
        AttributeCertificateRefs attributeCertificateRefs = (AttributeCertificateRefs) o;
        thingsList.add(attributeCertificateRefs);
      }
      if (o.getClass().equals(CertificateValues.class)) {
        CertificateValues certificateValues = (CertificateValues) o;
        thingsList.add(ObjectFactoryUtils.FACTORY_OASIS_DSSX
            .createUnsignedSignaturePropertiesTypeCertificateValues(
                mapCertificateValues(certificateValues.getValue()
                    .getEncapsulatedX509CertificateOrOtherCertificate())));
      }
      if (o.getClass().equals(RefsOnlyTimeStamp.class)) {
        RefsOnlyTimeStamp refsOnlyTimeStamp = (RefsOnlyTimeStamp) o;
        // TODO: mapTimestampValidity need to be fixed
        /*thingsList.add(ObjectFactoryUtils.FACTORY_OASIS_DSSX
            .createUnsignedSignaturePropertiesTypeRefsOnlyTimeStamp(
                mapTimestampValidity(refsOnlyTimeStamp.getValue(), validationObjectListType)));*/
      }
      if (o.getClass().equals(AttributeRevocationValues.class)) {
        AttributeRevocationValues attributeRevocationValues = (AttributeRevocationValues) o;
        thingsList.add(ObjectFactoryUtils.FACTORY_OASIS_DSSX
            .createUnsignedSignaturePropertiesTypeRevocationValues(
                mapRevocationValues(attributeRevocationValues.getValue(),
                    validationObjectListType)));
      }
      if (o.getClass().equals(CounterSignature.class)) {
        CounterSignature counterSignature = (CounterSignature) o;
        counterSignature.getValue().getSignature();
        ignoreSizeComparison = true;
        // todo : we do not handle the countersignatures
      }
      if (o.getClass().equals(CompleteCertificateRefs.class)) {
        CompleteCertificateRefs completeCertificateRefs = (CompleteCertificateRefs) o;
        thingsList.add(completeCertificateRefs);
      }
      if (o.getClass().equals(SigAndRefsTimeStamp.class)) {
        SigAndRefsTimeStamp sigAndRefsTimeStamp = (SigAndRefsTimeStamp) o;
        // TODO: mapTimestampValidity need to be fixed
        /*thingsList.add(ObjectFactoryUtils.FACTORY_OASIS_DSSX
            .createUnsignedSignaturePropertiesTypeSigAndRefsTimeStamp(
                mapTimestampValidity(sigAndRefsTimeStamp.getValue(), validationObjectListType)));*/
      }
      if (o.getClass().equals(CompleteRevocationRefs.class)) {
        CompleteCertificateRefs completeCertificateRefs = (CompleteCertificateRefs) o;
        thingsList.add(completeCertificateRefs);
      }
      if (o.getClass().equals(AttributeRevocationRefs.class)) {
        AttributeRevocationRefs attributeRevocationRefs = (AttributeRevocationRefs) o;
        thingsList.add(attributeRevocationRefs);
      }
      if (o.getClass().equals(AttrAuthoritiesCertValues.class)) {
        AttrAuthoritiesCertValues attrAuthoritiesCertValues = (AttrAuthoritiesCertValues) o;
        thingsList.add(
            ObjectFactoryUtils.FACTORY_OASIS_DSSX
                .createUnsignedSignaturePropertiesTypeCertificateValues(
                    mapCertificateValues(attrAuthoritiesCertValues.getValue()
                        .getEncapsulatedX509CertificateOrOtherCertificate())));
      }
      if (o.getClass().equals(
          eu.futuretrust.vals.jaxb.etsi.esi.xades.v141.ArchiveTimeStamp.class)) {
        eu.futuretrust.vals.jaxb.etsi.esi.xades.v141.ArchiveTimeStamp archiveTimeStamp = (eu.futuretrust.vals.jaxb.etsi.esi.xades.v141.ArchiveTimeStamp) o;
        // TODO: mapTimestampValidity need to be fixed
        /*thingsList.add(
            ObjectFactoryUtils.FACTORY_OASIS_DSSX
                .createUnsignedSignaturePropertiesTypeArchiveTimeStamp(
                    mapTimestampValidity(archiveTimeStamp.getValue(), validationObjectListType)));*/
      }

      if (o.getClass().equals(
          eu.futuretrust.vals.jaxb.etsi.esi.xades.v141.TimeStampValidationData.class)) {
        ignoreSizeComparison = true;
        // not handled YET by MultiVR
      }

      // nothing has been added here
      if (thingsList.size() == originalSize && !ignoreSizeComparison) {
        throw new DSSParserException(
            "Non expected element in signature " + o.getClass(),
            ResultMajor.REQUESTER_ERROR, ResultMinor.GENERAL_ERROR);
      }
    }
    return unsignedSignaturePropertiesTypeMULTI;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateValuesType mapCertificateValues(
      List<Object> encapsulatedX509CertificateOrOtherCertificate) {
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateValuesType certificateValuesTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createCertificateValuesType();
    certificateValuesTypeMULTI.getEncapsulatedX509CertificateOrOtherCertificate()
        .addAll(encapsulatedX509CertificateOrOtherCertificate);
    return certificateValuesTypeMULTI;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.RevocationValuesType mapRevocationValues(
      RevocationValuesType revocationValuesTypeXADES,
      ValidationObjectListType validationObjectListType) throws DSSParserException {
    if (revocationValuesTypeXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.RevocationValuesType revocationValuesTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createRevocationValuesType();
    revocationValuesTypeMULTI.setCRLValues(
        mapCRLValues(revocationValuesTypeXADES.getCRLValues(), validationObjectListType));
    revocationValuesTypeMULTI
        .setOCSPValues(
            mapOCSPValues(revocationValuesTypeXADES.getOCSPValues(), validationObjectListType));
    revocationValuesTypeMULTI.setId(revocationValuesTypeXADES.getId());
    return revocationValuesTypeMULTI;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.RevocationValuesType.OCSPValues mapOCSPValues(
      final OCSPValuesType ocspValuesXADES,
      final ValidationObjectListType validationObjectListType)
      throws DSSParserException {
    if (ocspValuesXADES == null) {
      return null;
    }

    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.RevocationValuesType.OCSPValues ocspValuesMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createRevocationValuesTypeOCSPValues();

    for (EncapsulatedPKIDataType encapsulatedPKIDataType : ocspValuesXADES
        .getEncapsulatedOCSPValue()) {
      Optional<ValidationObjectType> validationObjectTypeOptional = validationObjectsBuilderService
          .findByBase64(encapsulatedPKIDataType.getValue(), ValidationObjectTypeId.OCSPRESPONSE,
              validationObjectListType);
      if (validationObjectTypeOptional.isPresent()) {
        ocspValuesMULTI.getVerifiedOCSPResponse()
            .add(validationObjectTypeOptional.get().getIndividualOCSPReport());
      } else {
        throw new DSSParserException(
            "Could not find a validity report for a OCSP response in the signature",
            ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
      }
    }
    return ocspValuesMULTI;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.RevocationValuesType.CRLValues mapCRLValues(
      final CRLValuesType crlValuesXADES,
      final ValidationObjectListType validationObjectListType) throws DSSParserException {
    if (crlValuesXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.RevocationValuesType.CRLValues crlValuesMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createRevocationValuesTypeCRLValues();
    for (EncapsulatedPKIDataType encapsulatedPKIDataType : crlValuesXADES
        .getEncapsulatedCRLValue()) {
      Optional<ValidationObjectType> validationObjectTypeOptional = validationObjectsBuilderService
          .findByBase64(encapsulatedPKIDataType.getValue(), ValidationObjectTypeId.CRL,
              validationObjectListType);
      if (validationObjectTypeOptional.isPresent()) {
        crlValuesMULTI.getVerifiedCRL()
            .add(validationObjectTypeOptional.get().getIndividualCRLReport());
      } else {
        throw new DSSParserException(
            "Could not find a validity report for a CRL in the signature",
            ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
      }
    }
    return crlValuesMULTI;
  }

  @Override
  public eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedPropertiesType mapSignedProperties(
      final SignedPropertiesType signedPropertiesTypeXADES,
      final ValidationObjectListType validationObjectListType) throws DSSParserException {
    if (signedPropertiesTypeXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedPropertiesType signedPropertiesTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createSignedPropertiesType();
    signedPropertiesTypeMULTI.setSignedSignatureProperties(
        mapSignedSignatureProperties(signedPropertiesTypeXADES.getSignedSignatureProperties(),
            validationObjectListType));
    signedPropertiesTypeMULTI.setSignedDataObjectProperties(
        mapSignedDataObjectProperties(signedPropertiesTypeXADES.getSignedDataObjectProperties(),
            validationObjectListType));
    signedPropertiesTypeMULTI.setId(signedPropertiesTypeXADES.getId());
    return signedPropertiesTypeMULTI;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedSignaturePropertiesType mapSignedSignatureProperties(
      final SignedSignaturePropertiesType signedSignaturePropertiesXADES,
      final ValidationObjectListType validationObjectListType) {
    if (signedSignaturePropertiesXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedSignaturePropertiesType signedSignaturePropertiesTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createSignedSignaturePropertiesType();
    signedSignaturePropertiesTypeMULTI
        .setSigningTime(signedSignaturePropertiesXADES.getSigningTime());
    signedSignaturePropertiesTypeMULTI
        .setSigningCertificate(signedSignaturePropertiesXADES.getSigningCertificate());
    signedSignaturePropertiesTypeMULTI.setSignaturePolicyIdentifier(
        signedSignaturePropertiesXADES.getSignaturePolicyIdentifier());
    signedSignaturePropertiesTypeMULTI
        .setSignatureProductionPlace(signedSignaturePropertiesXADES.getSignatureProductionPlace());
    signedSignaturePropertiesTypeMULTI
        .setSignerRole(mapSignerRole(signedSignaturePropertiesXADES.getSignerRole(),
            validationObjectListType));
    return signedSignaturePropertiesTypeMULTI;
  }


  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignerRoleType mapSignerRole(
      final SignerRoleType signerRoleXADES,
      final ValidationObjectListType validationObjectListType) {
    if (signerRoleXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignerRoleType signerRoleTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createSignerRoleType();
    signerRoleTypeMULTI.setCertifiedRoles(
        mapCertifiedRoles(signerRoleXADES.getCertifiedRoles(), validationObjectListType));
    signerRoleTypeMULTI.setClaimedRoles(signerRoleXADES.getClaimedRoles());
    return signerRoleTypeMULTI;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertifiedRolesListType mapCertifiedRoles(
      final CertifiedRolesListType certifiedRolesXADES,
      final ValidationObjectListType validationObjectListType) {
    if (certifiedRolesXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertifiedRolesListType certifiedRolesListTypeMUTLI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createCertifiedRolesListType();
    List<AttributeCertificateValidityType> attributeCertificateValidityTypesList = new ArrayList<>();

    for (EncapsulatedPKIDataType encapsulatedPKIDataType : certifiedRolesXADES.getCertifiedRole()) {
      Optional<ValidationObjectType> optionalCertificateForRole = validationObjectsBuilderService
          .findByBase64(encapsulatedPKIDataType.getValue(), ValidationObjectTypeId.CERTIFICATE,
              validationObjectListType);
      if (optionalCertificateForRole.isPresent()) {
        ValidationObjectType certificateForRole = optionalCertificateForRole.get();
        AttributeCertificateValidityType attributeCertificateValidityType = mapAttributeCertificateValidityType(
            certificateForRole);
        attributeCertificateValidityTypesList.add(attributeCertificateValidityType);
      }
    }
    certifiedRolesListTypeMUTLI.getAttributeCertificateValidity()
        .addAll(attributeCertificateValidityTypesList);
    return certifiedRolesListTypeMUTLI;
  }

  private AttributeCertificateValidityType mapAttributeCertificateValidityType(
      ValidationObjectType certificateForRole) {
    if (certificateForRole == null) {
      return null;
    }
    AttributeCertificateValidityType attributeCertificateValidityType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createAttributeCertificateValidityType();
    CertificateValidityType certificateValidityType = certificateForRole
        .getIndividualCertificateReport();

    AttrCertIDType attrCertIDType = ObjectFactoryUtils.FACTORY_OASIS_DSSX.createAttrCertIDType();

    EntityType holder = ObjectFactoryUtils.FACTORY_OASIS_DSSX.createEntityType();
    // subject is RFC 4514 and holder is RFC 3275, it seems to correspond
    holder.setName(certificateValidityType.getSubject());
    holder.setBaseCertificateID(certificateValidityType.getCertificateIdentifier());

    EntityType issuer = ObjectFactoryUtils.FACTORY_OASIS_DSSX.createEntityType();
    issuer.setName(certificateValidityType.getCertificateIdentifier().getX509IssuerName());
    // element BaseCertificateID is optional...

    attrCertIDType.setHolder(holder);
    attrCertIDType.setIssuer(issuer);
    attrCertIDType
        .setSerialNumber(certificateValidityType.getCertificateIdentifier().getX509SerialNumber());

    // AttributeCertificateIdentifier
    attributeCertificateValidityType.setAttributeCertificateIdentifier(attrCertIDType);
    AttributeCertificateContentType attributeCertificateContentType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createAttributeCertificateContentType();
    attributeCertificateContentType
        .setVersion(certificateValidityType.getCertificateContent().getVersion());
    attributeCertificateContentType.setHolder(holder);
    attributeCertificateContentType.setIssuer(issuer);
    attributeCertificateContentType.setSignatureAlgorithm(
        certificateValidityType.getCertificateContent().getSignatureAlgorithm());
    attributeCertificateContentType
        .setSerialNumber(certificateValidityType.getCertificateContent().getSerialNumber());
    attributeCertificateContentType.setAttCertValidityPeriod(
        certificateValidityType.getCertificateContent().getValidityPeriod());

    // AttributeCertificateValue
    attributeCertificateValidityType
        .setAttributeCertificateValue(certificateForRole.getValidationObject().getBase64());

    // AttributeCertificateContent
    attributeCertificateValidityType
        .setAttributeCertificateContent(attributeCertificateContentType);

    // SignatureOK
    attributeCertificateValidityType.setSignatureOK(certificateValidityType.getSignatureOK());

    // CertificatePathValidity
    CertificatePathValidityType certificatePathValidityType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createCertificatePathValidityType();
    certificatePathValidityType.setPathValiditySummary(certificateValidityType.getChainingOK());
    certificatePathValidityType
        .setCertificateIdentifier(certificatePathValidityType.getCertificateIdentifier());
    attributeCertificateValidityType.setCertificatePathValidity(certificatePathValidityType);
    return attributeCertificateValidityType;
  }

  private eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedDataObjectPropertiesType mapSignedDataObjectProperties(
      final SignedDataObjectPropertiesType signedDataObjectPropertiesTypeXADES,
      final ValidationObjectListType validationObjectListType)
      throws DSSParserException {
    if (signedDataObjectPropertiesTypeXADES == null) {
      return null;
    }
    eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedDataObjectPropertiesType signedDataObjectPropertiesTypeMULTI = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createSignedDataObjectPropertiesType();
    signedDataObjectPropertiesTypeMULTI.getDataObjectFormat()
        .addAll(signedDataObjectPropertiesTypeXADES.getDataObjectFormat());
    signedDataObjectPropertiesTypeMULTI.getCommitmentTypeIndication()
        .addAll(signedDataObjectPropertiesTypeXADES.getCommitmentTypeIndication());
    // TODO: mapTimestampValidity need to be fixed
    /*signedDataObjectPropertiesTypeMULTI.getAllDataObjectsTimeStamp().addAll(
        mapTimeStampValidity(signedDataObjectPropertiesTypeXADES.getAllDataObjectsTimeStamp(),
            validationObjectListType));
    signedDataObjectPropertiesTypeMULTI.getIndividualDataObjectsTimeStamp().addAll(
        mapTimeStampValidity(
            signedDataObjectPropertiesTypeXADES.getIndividualDataObjectsTimeStamp(),
            validationObjectListType));*/
    signedDataObjectPropertiesTypeMULTI.setId(signedDataObjectPropertiesTypeXADES.getId());
    return signedDataObjectPropertiesTypeMULTI;
  }

  private List<TimeStampValidityType> mapTimeStampValidity(
      final List<XAdESTimeStampType> xAdESTimeStampTypeList,
      final ValidationObjectListType validationObjectListType) throws DSSParserException {
    List<TimeStampValidityType> timeStampValidityTypeList = new ArrayList<>();
    for (XAdESTimeStampType timeStampType : xAdESTimeStampTypeList) {
      timeStampValidityTypeList.add(mapTimestampValidity(timeStampType, validationObjectListType));
    }
    return timeStampValidityTypeList;
  }


  private TimeStampValidityType mapTimestampValidity(final XAdESTimeStampType xAdESTimeStampType,
      final ValidationObjectListType validationObjectListType)
      throws DSSParserException {
    for (Object o : xAdESTimeStampType.getEncapsulatedTimeStampOrXMLTimeStamp()) {
      if (o instanceof EncapsulatedPKIDataType) {
        EncapsulatedPKIDataType encapsulatedPKIData = (EncapsulatedPKIDataType) o;
        Optional<ValidationObjectType> optionalTimestamp = validationObjectsBuilderService
            .findByBase64(encapsulatedPKIData.getValue(), ValidationObjectTypeId.TIMESTAMP,
                validationObjectListType);
        if (optionalTimestamp.isPresent()) {
          return optionalTimestamp.get().getIndividualTimeStampReport();
        }
      }
    }
    throw new DSSParserException(
        "Could not find a validity report for a timestamp in the signature",
        ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
  }


}
