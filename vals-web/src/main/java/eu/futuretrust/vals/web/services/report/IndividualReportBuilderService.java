package eu.futuretrust.vals.web.services.report;

import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.DigestAlgAndValueType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.IndividualReportType;
import eu.futuretrust.vals.protocol.exceptions.MessageDigestException;
import eu.futuretrust.vals.protocol.exceptions.VerifyResponseException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.output.Certificate;
import eu.futuretrust.vals.protocol.output.Crl;
import eu.futuretrust.vals.protocol.output.Ocsp;
import eu.futuretrust.vals.protocol.output.Timestamp;
import java.util.List;
import javax.xml.datatype.XMLGregorianCalendar;

public interface IndividualReportBuilderService {

  List<IndividualReportType> generate(
      SignatureWrapper signatureWrapper,
      XMLGregorianCalendar validationTime,
      SignedObject signedObject,
      SimpleReport simpleReport,
      DiagnosticData diagnosticData,
      List<byte[]> signersDocument,
      Policy policy,
      List<Certificate> certificateVOs,
      List<Timestamp> listPOE,
      List<Ocsp> ocspVOs,
      List<Crl> crlVOs,
      MainIndication mainIndication,
      SubIndication subIndication) throws VerifyResponseException;

  DigestAlgAndValueType createDigestAlgAndValue(byte[] toBeDigested)
      throws MessageDigestException;
}
