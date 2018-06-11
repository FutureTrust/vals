package eu.futuretrust.vals.protocol.validation.validity;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CRLIdentifierType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CRLValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificatePathValidityType;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import eu.futuretrust.vals.protocol.validation.DSSRevocationWrapperParser;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * A DSSCRLValidityParser is an object which proposes to parse the CRLValidity of a
 * RevocationWrapper
 */
public class DSSCRLValidityParser {

  private DiagnosticData diagnosticData;
  private RevocationWrapper revocationWrapper;
  private CRLValidityType crlValidityType;

  public DSSCRLValidityParser(DiagnosticData diagnosticData, RevocationWrapper revocationWrapper) {
    this.diagnosticData = diagnosticData;
    this.revocationWrapper = revocationWrapper;
    this.crlValidityType = new CRLValidityType();
  }


  /**
   * Returns a CRLValidityType element for the timestamp given to the constructor
   *
   * @throws DSSParserException : whenever a problem occurs in the parsing of an element in the
   * diagnostic data
   */
  public CRLValidityType getCRLValidity() throws DSSParserException {
    addCRLIdentifier();
    addSignatureOk();
    addCertificatePathValidity();
    return crlValidityType;
  }

  /**
   * Adds a CertificatePathValidity element to the CRLValidityType <br> [DSS-Multi] This element
   * contains the result of the validity check of the certificate
   */
  private void addCertificatePathValidity() {
    DSSCertificatePathValidityParser dssCertificatePathValidityParser = new DSSCertificatePathValidityParser(
        diagnosticData.getUsedCertificateById(revocationWrapper.getSigningCertificateId()));
    CertificatePathValidityType certificatePathValidity = dssCertificatePathValidityParser
        .getCertificatePathValidityType();
    crlValidityType.setCertificatePathValidity(certificatePathValidity);
  }

  /**
   * Adds a SignatureOk element to the CRLValidityType <br> [DSS-Multi] This element indicates,
   * whether the digital signature is mathematically valid or not
   */
  private void addSignatureOk() {
    DSSSignatureValidityParser dssSignatureValidityParser = new DSSSignatureValidityParser(
        revocationWrapper.isSignatureValid());
    crlValidityType.setSignatureOK(dssSignatureValidityParser.getSignatureValidityType());
  }

  /**
   * Adds a CRLIdentifier to the CRLValidityType [DSS-Multi] This element refers to an X.509v2 CRL
   * according to [RFC5280].
   *
   * @throws DSSParserException : whenever an error occurs in the parsing of the CRL's issuer from
   * its signing certificate.
   */
  private void addCRLIdentifier() throws DSSParserException {
    CRLIdentifierType crlIdentifier = new CRLIdentifierType();

    // Adds the Issuer
    DSSCertificateWrapperParser dssCertificateWrapperParser = new DSSCertificateWrapperParser();
    XmlCertificate xmlCertificate = dssCertificateWrapperParser
        .getXmlCertificateField(
            diagnosticData.getUsedCertificateById(revocationWrapper.getSigningCertificateId()));
    String responderIdName = xmlCertificate.getSubjectDistinguishedName().get(1).getValue();
    crlIdentifier.setIssuer(responderIdName);

    // Adds the IssueTime
    XMLGregorianCalendar issueTime = XMLGregorianCalendarBuilder
        .createXMLGregorianCalendar(revocationWrapper.getProductionDate());
    crlIdentifier.setIssueTime(issueTime);

    // Adds the URI
    crlIdentifier.setURI((new DSSRevocationWrapperParser()).getXmlRevocationField(revocationWrapper)
        .getSourceAddress());
    crlValidityType.setCRLIdentifier(crlIdentifier);
  }

}
