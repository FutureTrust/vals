package eu.futuretrust.vals.web.services.report;


import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationReportData;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationReportDataType;
import eu.futuretrust.vals.protocol.enums.RevocationReason;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import eu.futuretrust.vals.protocol.exceptions.ValidationObjectException;
import eu.futuretrust.vals.protocol.exceptions.ValidationReportDataException;
import eu.futuretrust.vals.protocol.input.Policy;
import java.util.Date;
import java.util.List;

public interface ValidationReportDataBuilderService {

  void setCertificateChain(List<byte[]> certificateChainAVRD,
      ValidationReportDataType validationReportData,
      ValidationObjectListType validationObjectListType) throws ValidationObjectException;

  void setAdditionalData(final String type,
      final Object element,
      final ValidationReportDataType validationReportData);

  ValidationReportData generate(SignatureWrapper signatureWrapper,
      Policy policy,
      DiagnosticData diagnosticData,
      SimpleReport simpleReport,
      MainIndication mainIndication,
      SubIndication subIndication,
      ValidationObjectListType validationObjectListType)
      throws ValidationObjectException, ValidationReportDataException;

  /**
   * Add the Signing Certificate into the Associated Validation Report Data
   *
   * @param x509base64 base64 representation of the certificate
   * @throws ValidationObjectException Whenever the certificate represented by {@code x509base64}
   * cannot be retrieved from the Validation Objects
   */
  void setSigningCertificate(byte[] x509base64,
      final ValidationReportDataType validationReportData,
      final ValidationObjectListType validationObjectListType)
      throws ValidationObjectException;

  /**
   * Add a Revocation Status Information Element in the Associated Validation Report Data
   *
   * @param x509CertificateBase64 base64 representation of the certificate which is revoked
   * @param revocationTime moment of revocation
   * @param revocationReason reason of revocation
   * @param revocationDataBase64 revocation data encoded in base 64
   * @param voType either CRL or OCSP response
   */
  void setRevocationStatusInformationElement(final byte[] x509CertificateBase64,
      final Date revocationTime,
      final RevocationReason revocationReason,
      final byte[] revocationDataBase64,
      final ValidationObjectTypeId voType,
      final ValidationObjectListType validationObjectListType,
      final ValidationReportDataType validationReportDataType)
      throws ValidationObjectException, ValidationReportDataException;

  /**
   * Add the Signed Data Objects into the Associated Validation Report Data
   *
   * @param base64List base64 representation of the certificate chain
   */
  void setSignedDataObjects(final List<byte[]> base64List,
      final ValidationReportDataType validationReportData,
      final ValidationObjectListType validationObjectListType) throws ValidationObjectException;

}
