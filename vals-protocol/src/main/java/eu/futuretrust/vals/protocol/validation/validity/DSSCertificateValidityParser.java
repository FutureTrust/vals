package eu.futuretrust.vals.protocol.validation.validity;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateContentType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateStatusType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateStatusType.RevocationInfo;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificateValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.ValidityPeriodType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.VerificationResultType;
import eu.futuretrust.vals.jaxb.oasis.xmldsig.core.X509IssuerSerialType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import eu.futuretrust.vals.protocol.enums.RevocationReason;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.xml.datatype.XMLGregorianCalendar;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;

public class DSSCertificateValidityParser {

  private CertificateWrapper certificateWrapper;
  private Date certificateValidityFromReferencePoint;
  private CertificateValidityType certificateValidityType;

  public DSSCertificateValidityParser(CertificateWrapper certificateWrapper,
      Date validityReferencePoint) {
    this.certificateValidityFromReferencePoint = validityReferencePoint;
    this.certificateWrapper = certificateWrapper;
    this.certificateValidityType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createCertificateValidityType();
  }

  /**
   * Returns a CertificateValidityType for the certificate identified by {@code certID} in {@code
   * diagnosticData} and for the moment given by {@code referencePoint}
   */
  public CertificateValidityType getCertificateValidity() throws DSSParserException {
    addCertificateIdentifierAndSubject();
    addValidityPeriodOk();
    addExtensionOK();
    addCertificateContent();
    addCertificateStatus();
    return certificateValidityType;
  }

  /**
   * Adds a CertificateContent to the CertificateValidityType <br> [DSS-Multi] This element contains
   * detailed information about the content of the certificate
   *
   * @throws DSSParserException when a problem occurs in the parsing of the X509 certificate
   */
  private void addCertificateContent() throws DSSParserException {
    CertificateContentType certificateContentType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createCertificateContentType();

      certificateContentType.setVersion((BigInteger.valueOf(certificateWrapper.getVersion())));
      certificateContentType.setSerialNumber(new BigInteger(certificateWrapper.getSerialNumber()));
      certificateContentType.setSignatureAlgorithm(certificateWrapper.getEncryptionAlgoUsedToSignThisToken());
      certificateContentType.setIssuer(certificateWrapper.getCertificateIssuerDN());

      ValidityPeriodType validityPeriod = ObjectFactoryUtils.FACTORY_OASIS_DSSX
          .createValidityPeriodType();
      validityPeriod.setNotBefore(
          XMLGregorianCalendarBuilder.createXMLGregorianCalendar(certificateWrapper.getNotBefore()));
      validityPeriod
          .setNotAfter(XMLGregorianCalendarBuilder.createXMLGregorianCalendar(certificateWrapper.getNotAfter()));
      certificateContentType.setValidityPeriod(validityPeriod);
      certificateContentType.setSubject(certificateWrapper.getCertificateDN());
  }


  /**
   * Adds a CertificateStatus to the CertificateValidityType <br> [DSS-Multi ] This element contains
   * information about the result of the certificate revocation check
   */
  private void addCertificateStatus() {
    CertificateStatusType certificateStatusType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createCertificateStatusType();
    VerificationResultType certStatusOk = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createVerificationResultType();

    if (!certificateWrapper.isRevoked()) {
      certStatusOk.setResultMajor(MainIndication.TOTAL_PASSED.getURI());
    } else {
      certStatusOk.setResultMajor(MainIndication.TOTAL_FAILED.getURI());
      RevocationWrapper revocationWrapper = certificateWrapper.getLatestRevocationData();

      // Adding RevocationInfo
      RevocationInfo revocationInfo = ObjectFactoryUtils.FACTORY_OASIS_DSSX
          .createCertificateStatusTypeRevocationInfo();

      // Adding Revocation Date
      XMLGregorianCalendar revocationTimeGrego = XMLGregorianCalendarBuilder
          .createXMLGregorianCalendar(revocationWrapper.getRevocationDate());
      revocationInfo.setRevocationDate(revocationTimeGrego);

      // Adding RevocationReason
      VerificationResultType validationResultType = ObjectFactoryUtils.FACTORY_OASIS_DSSX
          .createVerificationResultType();
      String reason = revocationWrapper.getReason();
      RevocationReason revocationReasonURI = null;
      if (StringUtils.isNotEmpty(reason)) {
        revocationReasonURI = RevocationReason.fromURI(reason);
      }
      validationResultType.setResultMajor(revocationReasonURI != null?
          revocationReasonURI.getURI() : RevocationReason.UNSPECIFIED.getURI());
      revocationInfo.setRevocationReason(validationResultType);
      certificateStatusType.setRevocationInfo(revocationInfo);
    }
    certificateStatusType.setCertStatusOK(certStatusOk);
    certificateValidityType.setCertificateStatus(certificateStatusType);
  }

  /**
   * Adds an always true extensionOK to {@code certificateValidityType} since DSS does not support
   * certificates' extensions validation.
   */
  private void addExtensionOK() {
    VerificationResultType extensionsOK = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createVerificationResultType();
    extensionsOK.setResultMajor(MainIndication.TOTAL_PASSED.getURI());
    certificateValidityType.setExtensionsOK(extensionsOK);
  }

  /**
   * Adds a ValidityPeriodOk element to CertificateValidityType <br> [DSS-Multi] This element
   * indicates, whether the reference point in time is within the validity period of the
   * certificate
   */
  private void addValidityPeriodOk() {
    VerificationResultType validityPeriodOk = ObjectFactoryUtils.FACTORY_OASIS_DSSX
        .createVerificationResultType();

    if (certificateValidityFromReferencePoint == null) {
      validityPeriodOk.setResultMajor(MainIndication.TOTAL_FAILED.getURI());
    } else if (certificateWrapper.getNotBefore().before(certificateValidityFromReferencePoint)
        && certificateWrapper.getNotAfter()
        .after(certificateValidityFromReferencePoint)) {
      validityPeriodOk.setResultMajor(MainIndication.TOTAL_PASSED.getURI());
    } else {
      validityPeriodOk.setResultMajor(MainIndication.TOTAL_FAILED.getURI());
    }
    certificateValidityType.setValidityPeriodOK(validityPeriodOk);
  }

  /**
   * Adds a CertificateIdentifier and a Subject to {@code certificateValidityType} from the
   * X509Certificate with the id {@code certID} in {@code diagnosticData}.
   *
   * @throws DSSParserException : Whenever an error occurs when trying to parse the
   * CertificateIdentifier or the Subject on the certificate given in the {@code diagnosticData}
   */
  private void addCertificateIdentifierAndSubject() throws DSSParserException {
    DSSCertificateWrapperParser dssCertificateWrapperParser = new DSSCertificateWrapperParser();
    XmlCertificate xmlCertificate = dssCertificateWrapperParser
        .getXmlCertificateField(certificateWrapper);

    // CertificateIdentifier is mandatory
    // x509IssuerSerialType contains a unique reference to the certificate whose path has been checked.
    X509IssuerSerialType x509IssuerSerialType = ObjectFactoryUtils.FACTORY_XML_DSIG
        .createX509IssuerSerialType();
    x509IssuerSerialType.setX509IssuerName(certificateWrapper.getCertificateIssuerDN());
    x509IssuerSerialType
        .setX509SerialNumber((new BigInteger(certificateWrapper.getSerialNumber())));
    certificateValidityType.setCertificateIdentifier(x509IssuerSerialType);

    // Subject is mandatory
    certificateValidityType
        .setSubject(xmlCertificate.getSubjectDistinguishedName().get(1).getValue());
  }

}


