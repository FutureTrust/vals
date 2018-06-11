package eu.futuretrust.vals.core.x509;

import eu.futuretrust.vals.core.etsi.esi.ValidationResult;
import eu.futuretrust.vals.core.etsi.esi.exceptions.CertificateValidationException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by rochafr on 04/08/2017.
 */
public interface X509Validation {

  ValidationResult validate(X509Certificate x509Cert, X509CVParameters params)
    throws CertificateValidationException;

  ValidationResult validate(X509Certificate x509Cert, List<X509Certificate> certPath,
      X509CVParameters params) throws CertificateValidationException;

  ValidationResult validate(X509Certificate x509Cert, List<X509Certificate> certPath)
    throws CertificateValidationException;

  ValidationResult validate(X509Certificate x509Cert) throws CertificateValidationException;

}
