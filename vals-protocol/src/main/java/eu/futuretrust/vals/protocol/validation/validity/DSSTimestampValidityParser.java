package eu.futuretrust.vals.protocol.validation.validity;

import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.CertificatePathValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.TimeStampValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.VerificationResultType;

/**
 * A DSSTimestampValidityParser is an object which proposes to parse the TimeStampValidity of a
 * TimestampWrapper
 */
public class DSSTimestampValidityParser {

  private DiagnosticData diagnosticData;
  private TimestampWrapper timestampWrapper;
  private TimeStampValidityType timeStampValidityType;

  public DSSTimestampValidityParser(DiagnosticData diagnosticData,
      TimestampWrapper timestampWrapper) {
    this.diagnosticData = diagnosticData;
    this.timestampWrapper = timestampWrapper;
    this.timeStampValidityType = new TimeStampValidityType();
  }

  /**
   * Returns a TimeStampValidityType element for the timestamp given to the constructor
   */
  public TimeStampValidityType getTimestampValidity() {
    addFormatOk();
    addSignatureOk();
    addCertificatePathValidity();
    return timeStampValidityType;
  }

  /**
   * Adds a CertificatePathValidity element to the timeStampValidityType [DSS-Multi] This element
   * contains the result of the validity check of the certificate
   */
  private void addCertificatePathValidity() {
    DSSCertificatePathValidityParser dssCertificatePathValidityParser = new DSSCertificatePathValidityParser(
        diagnosticData.getUsedCertificateById(timestampWrapper.getSigningCertificateId()));
    CertificatePathValidityType certificatePathValidity = dssCertificatePathValidityParser
        .getCertificatePathValidityType();
    timeStampValidityType.setCertificatePathValidity(certificatePathValidity);
  }

  /**
   * Adds an always true FormatOk element to the timestampValidityType, since the timestamp in
   * assumed to have been extracted correctly [DSS-Multi] This element indicates, whether the format
   * of the time stamp is ok or not
   */
  private void addFormatOk() {
    VerificationResultType formatOk = new VerificationResultType();
    formatOk.setResultMajor(MainIndication.TOTAL_PASSED.getURI());
    timeStampValidityType.setFormatOK(formatOk);
  }

  /**
   * Adds a SignatureOk element to the timestampValidityType [DSS-Multi] This element indicates,
   * whether the digital signature is mathematically valid or not
   */
  private void addSignatureOk() {
    DSSSignatureValidityParser dssSignatureValidityParser = new DSSSignatureValidityParser(
        timestampWrapper.isSignatureValid());
    timeStampValidityType.setSignatureOK(dssSignatureValidityParser.getSignatureValidityType());
  }


}
