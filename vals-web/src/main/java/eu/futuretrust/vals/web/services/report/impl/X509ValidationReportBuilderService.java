package eu.futuretrust.vals.web.services.report.impl;

import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.SimpleCertificateReport;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.futuretrust.vals.core.manifest.exceptions.ManifestException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.exceptions.SignedObjectException;
import eu.futuretrust.vals.protocol.exceptions.VerifyResponseException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import eu.futuretrust.vals.web.services.report.ValidationReportBuilderService;
import eu.futuretrust.vals.web.services.response.CertificateVerifierService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

@Service
public class X509ValidationReportBuilderService implements ValidationReportBuilderService {

  private CertificateVerifierService certificateVerifierService;

  @Autowired
  public X509ValidationReportBuilderService(final CertificateVerifierService certificateVerifierService) {
    this.certificateVerifierService = certificateVerifierService;
  }

  @Override
  public ValidationReport generate(VerifyRequestType verifyRequest,
                                   SignedObject signedObject,
                                   Policy policy,
                                   List<InputDocument> inputDocuments,
                                   DSSResponseType responseType)
  {
    try
    {
      CertificateToken token = new CertificateToken(getCertificate(signedObject));
      CertificateValidator validator = CertificateValidator.fromCertificate(token);
      validator.setCertificateVerifier(certificateVerifierService.getCertificateVerifier());
      CertificateReports reports = validator.validate();

      SimpleCertificateReport simpleReport = reports.getSimpleReport();
    } catch (CertificateException e)
    {
      e.printStackTrace();
    }
    return null;
  }

  private X509Certificate getCertificate(final SignedObject signedObject) throws CertificateException
  {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) factory.generateCertificate(
            new ByteArrayInputStream(signedObject.getContent()));
  }
}
