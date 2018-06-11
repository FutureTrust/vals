package eu.futuretrust.vals.protocol.validation.validity;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.OCSPIdentifierType;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.ResponderIDType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificatePathValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.OCSPValidityType;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import eu.futuretrust.vals.protocol.helpers.XMLGregorianCalendarBuilder;
import eu.futuretrust.vals.protocol.validation.DSSCertificateWrapperParser;
import eu.futuretrust.vals.protocol.validation.DSSRevocationWrapperParser;
import java.util.Date;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * A DSSOCSPValidityParser is an object which proposes to parse the OCSPValidity of a
 * RevocationWrapper
 */
public class DSSOCSPValidityParser {

  private DiagnosticData diagnosticData;
  private RevocationWrapper revocationWrapper;
  private OCSPValidityType ocspValidityType;

  public DSSOCSPValidityParser(DiagnosticData diagnosticData, RevocationWrapper revocationWrapper) {
    this.diagnosticData = diagnosticData;
    this.revocationWrapper = revocationWrapper;
    this.ocspValidityType = new OCSPValidityType();
  }

  /**
   * Returns a OCSPValidityType element for the timestamp given to the constructor
   *
   * @throws DSSParserException : whenever a problem occurs in the parsing of an element in the
   * diagnostic data
   */
  public OCSPValidityType getOCSPValidity()
      throws DSSParserException {
    addOCSPIdentifier();
    addSignatureOk();
    addCertificatePathValidity();
    return ocspValidityType;
  }

  /**
   * Adds a OCSPIdentifier to the OCSPValidityType <br>[DSS-Multi] This element refers to an OCSP
   * response according to [RFC2560].
   *
   * @throws DSSParserException : whenever an error occurs while parsing info from the OCSP's
   * Certificate
   */
  private void addOCSPIdentifier() throws DSSParserException {
    OCSPIdentifierType ocspIdentifier = new OCSPIdentifierType();

    // add ResponderID - which is the issuer of the OCSP
    ResponderIDType responderID = new ResponderIDType();
    DSSCertificateWrapperParser dssCertificateWrapperParser = new DSSCertificateWrapperParser();
    XmlCertificate xmlCertificate = dssCertificateWrapperParser
        .getXmlCertificateField(
            diagnosticData.getUsedCertificateById(revocationWrapper.getSigningCertificateId()));

    String responderIdName = xmlCertificate.getIssuerDistinguishedName().get(1).getValue();
    responderID.setByName(responderIdName);
    ocspIdentifier.setResponderID(responderID);

    // add ProducedAt
    Date productionDate = revocationWrapper.getProductionDate();
    XMLGregorianCalendar gregorianDate = XMLGregorianCalendarBuilder
        .createXMLGregorianCalendar(productionDate);
    ocspIdentifier.setProducedAt(gregorianDate);

    // Adds the URI
    ocspIdentifier.setURI(
        (new DSSRevocationWrapperParser()).getXmlRevocationField(revocationWrapper)
            .getSourceAddress());

    ocspValidityType.setOCSPIdentifier(ocspIdentifier);
  }


  /**
   * Adds a SignatureOk element to the ocspValidityType <br> [DSS-Multi] This element indicates,
   * whether the digital signature is mathematically valid or not
   */
  private void addSignatureOk() {
    DSSSignatureValidityParser dssSignatureValidityParser = new DSSSignatureValidityParser(
        revocationWrapper.isSignatureValid());
    ocspValidityType.setSignatureOK(dssSignatureValidityParser.getSignatureValidityType());
  }


  /**
   * Adds a CertificatePathValidity element to the OCSPValidityType <br> [DSS-Multi] This element
   * contains the result of the validity check of the certificate
   */
  private void addCertificatePathValidity() {
    DSSCertificatePathValidityParser dssCertificatePathValidityParser = new DSSCertificatePathValidityParser(
        diagnosticData.getUsedCertificateById(revocationWrapper.getSigningCertificateId()));
    CertificatePathValidityType certificatePathValidity = dssCertificatePathValidityParser
        .getCertificatePathValidityType();
    ocspValidityType.setCertificatePathValidity(certificatePathValidity);
  }

}
