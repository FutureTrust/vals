/*
 * Copyright (c) 2017 European Commission.
 *
 *  Licensed under the EUPL, Version 1.1 or – as soon they will be approved by the European Commission - subsequent
 *  versions of the EUPL (the "Licence").
 *  You may not use this work except in compliance with the Licence.
 *  You may obtain a copy of the Licence at: https://joinup.ec.europa.eu/software/page/eupl5
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on
 *  an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 */

package eu.futuretrust.vals.core.timestamp;

import eu.futuretrust.vals.core.etsi.esi.ValidationResult;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.core.etsi.esi.exceptions.SignatureValidationException;
import eu.futuretrust.vals.core.etsi.esi.exceptions.TimeStampValidationException;
import eu.futuretrust.vals.core.x509.X509CertificateValidator;
import eu.futuretrust.vals.core.x509.X509Identifiers;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.EncapsulatedPKIDataType;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.CollectionStore;

/**
 * <p>
 * Code mostly based on https://tools.ietf.org/html/rfc5652#section-5 RFC 5652 obsoletes 3852
 */
public class TimeStampValidator {

  /**
   * SignedData ::= SEQUENCE { version CMSVersion, digestAlgorithms DigestAlgorithmIdentifiers,
   * encapContentInfo EncapsulatedContentInfo, certificates [0] IMPLICIT CertificateSet OPTIONAL,
   * crls [1] IMPLICIT RevocationInfoChoices OPTIONAL, signerInfos SignerInfos }
   * <p>
   * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
   * <p>
   * SignerInfos ::= SET OF SignerInfo
   */
  private CMSSignedData signedData;
  // collect all certificates
  // certificates [0] IMPLICIT CertificateSet OPTIONAL
  private Map<X500Principal, X509Certificate> certificates;
  // list of signer certificates index by serial number
  private Map<BigInteger, X509CertificateStatus> signersCertificates;
  // Base64 encoded trust points, useful for policy checks
  private List<String> trustPoints;

  private Map<X509Certificate, List<X509Certificate>> chains;

  private static TimeStampValidator instance = null;

  private TimeStampValidator() {
  }

  public static TimeStampValidator getInstance() {
    if (instance == null) {
      instance = new TimeStampValidator();
    }

    instance.reset();

    return instance;
  }

  /**
   * Validate one or more time stamp objects
   *
   * @param timeStampObjs list of time stamp objects to validate
   * @return return value of {@link #validateCMSTimeStamp() validateCMSTimeStamp} INVALID, if the
   * time stamp entry is not in the expected format
   */
  public ValidationResult validate(List<Object> timeStampObjs) throws SignatureValidationException {
    if (timeStampObjs == null) {
      throw new SignatureValidationException(
          "No timestamp objects to process, null or empty list.");
    }

    for (Object obj : timeStampObjs) {
      if (obj instanceof EncapsulatedPKIDataType) {
        byte[] stampdata = Base64.getDecoder().decode(((EncapsulatedPKIDataType) obj).getValue());
        ValidationResult ret;
        try {
          this.init(stampdata);
          ret = this.validateCMSTimeStamp();
        } catch (TimeStampValidationException e) {
          throw new SignatureValidationException(e.getMessage(), e);
        }
        return ret;
      }
    }
    return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.NO_POE);
  }

  /**
   * Validate a single time stamp object
   *
   * @param timeStamp, byte representation (encapsulated PKI data) of time stamp object
   * @return res, validation result object with feedback from validation process
   */
  public ValidationResult validate(byte[] timeStamp) throws SignatureValidationException {
    if (timeStamp == null) {
      throw new SignatureValidationException("No timestamp object to process.");
    }

    ValidationResult res;

    try {
      this.init(timeStamp);
      res = this.validateCMSTimeStamp();
    } catch (TimeStampValidationException e) {
      throw new SignatureValidationException(e.getMessage(), e);
    }

    return res;
  }

  /**
   * Auxiliary method to check the certificate in CertificateValues for LT(A) signatures
   */
  public List<X509Certificate> getCertPath(byte[] timeStamp) throws SignatureValidationException {
    if (timeStamp == null) {
      throw new SignatureValidationException("No timestamp object to process.");
    }

    try {
      this.init(timeStamp);
      List<X509Certificate> path = new ArrayList<>();
      path.addAll(this.certificates.values());
      return path;
    } catch (TimeStampValidationException e) {
      throw new SignatureValidationException(e.getMessage(), e);
    }
  }

  /**
   * to avoid the possibility of policy bypasses recurring to previously collected certificate data
   * not sure if possible, just adding as a preventive measure
   */
  private void reset() {
    this.signedData = null;
    this.certificates = new HashMap<>();
    this.signersCertificates = new HashMap<>();
    this.trustPoints = new ArrayList<>();
    this.chains = new HashMap<>();
  }

  /**
   * Retrieves the CMS data to process and extracts and validates the associated certificate data
   *
   * @param cmsProcessableData raw processable CMS data
   */
  private void init(byte[] cmsProcessableData) throws TimeStampValidationException {

    try {
      this.signedData = new CMSSignedData(cmsProcessableData);
    } catch (CMSException e) {
      throw new TimeStampValidationException(e.getMessage(), e);
    }

    // collect certificates from the TimeStamp's certificate store
    this.collectCertificateData();
    this.validateCertData();
  }

  public CMSSignedData getSignedData() {
    return signedData;
  }

  public Map<X500Principal, X509Certificate> getCertificates() {
    return certificates;
  }

  public List<String> getTrustPoints() {
    return this.trustPoints;
  }

  public Map<BigInteger, X509CertificateStatus> getSignersCertificates() {
    return signersCertificates;
  }

  public Map<X509Certificate, List<X509Certificate>> getChains() {
    return chains;
  }

  /**
   * Per-signer information is represented in the type SignerInfo:
   * <p>
   * RFC 5652 When the collection represents more than one signature, the successful validation of
   * one signature from a given signer ought to be treated as a successful signature by that
   * signer.
   * <p>
   * SignerInfo ::= SEQUENCE { version CMSVersion, sid SignerIdentifier, digestAlgorithm
   * DigestAlgorithmIdentifier, signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
   * signatureAlgorithm SignatureAlgorithmIdentifier, signature SignatureValue, unsignedAttrs [1]
   * IMPLICIT UnsignedAttributes OPTIONAL }
   *
   * @return VALID, if the time stamp is valid INDETERMINATE, if the validation of the time stamp
   * entry is not successful
   */
  private ValidationResult validateCMSTimeStamp() throws TimeStampValidationException {
    CMSSignedData signedData = this.getSignedData();
    Collection<SignerInformation> csi = signedData.getSignerInfos().getSigners();
    Map<BigInteger, X509CertificateStatus> signersStatus = this.getSignersCertificates();

    ValidationResult ret = null;

    for (SignerInformation si : csi) {

      X509CertificateStatus status = signersStatus.get(si.getSID().getSerialNumber());
      if (status.isValid()) {
        if (!signedData.getDigestAlgorithmIDs().contains(si.getDigestAlgorithmID())) {
          throw new TimeStampValidationException(
              "Invalid digest algorithm: " + si.getDigestAlgorithmID().getAlgorithm()
          );
        }

        try {
          // Verify that the given verifier can successfully verify the signature on this SignerInfo object.
          if (si.verify(
              new JcaSimpleSignerInfoVerifierBuilder().build(status.getX509Certificate()))) {
            ret = new ValidationResult(MainIndication.TOTAL_PASSED);
          }
        } catch (Exception e) {
          ret = new ValidationResult(MainIndication.INDETERMINATE, SubIndication.NO_POE,
              Collections.singletonList(e.getMessage()));
        }
      } else {
        ret = status.getResult();
      }
    }

    return ret;
  }

  private void validateCertData() throws TimeStampValidationException {
    X509CertificateValidator x509CertificateValidator = X509CertificateValidator.getInstance();
    //Map<X509Certificate, List<X509Certificate>> chains = this.getCertificateChains();
    List<IssuerSerial> signersIds = new ArrayList<>();

    this.getCertificateChains();
    if (this.chains.isEmpty()) {
      throw new TimeStampValidationException("Could not retrieve certificate chain(s).");
    }
    Set<X509Certificate> signersCerts = this.chains.keySet();
    for (X509Certificate key : signersCerts) {
      List<X509Certificate> path = this.chains.get(key);
      path.add(0, key);
      try {
        signersIds.add(new IssuerSerial(
            X500Name
                .getInstance(ASN1Sequence.fromByteArray(key.getIssuerX500Principal().getEncoded())),
            key.getSerialNumber()));
        ValidationResult ret = x509CertificateValidator.validate(key, path);
        if (ret.getMainIndication() == MainIndication.TOTAL_PASSED) {
          this.signersCertificates.put(key.getSerialNumber(),
              new X509CertificateStatus(key, true));
        } else {
          this.signersCertificates.put(key.getSerialNumber(),
              new X509CertificateStatus(key, false, ret));
        }
      } catch (Exception e) {
        throw new TimeStampValidationException(e.getMessage(), e);
      }
    }

    if (!this.checkSigningCerts(signersIds)) {
      throw new TimeStampValidationException(
          "Unauthorized signing certificates are not allowed. Prevention against substitution and re-issue attacks.");
    }
  }

  /**
   * RFC 2634 (https://tools.ietf.org/html/rfc2634#section-5.4)
   * <p>
   * The signing certificate attribute is designed to prevent the simple substitution and re-issue
   * attacks, and to allow for a restricted set of authorization certificates to be used in
   * verifying a signature.
   * <p>
   * OIDs: org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers; org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
   */
  private boolean checkSigningCerts(List<IssuerSerial> issuerSerials) {
    Collection<SignerInformation> csi = this.getSignedData().getSignerInfos().getSigners();
    List<IssuerSerial> authCerts = new ArrayList<>();
    for (SignerInformation si : csi) {
      AttributeTable at = si.getSignedAttributes();

      if (at.size() > 0 && at.get(PKCSObjectIdentifiers.id_aa_signingCertificate) != null) {
        Attribute signingCert = at.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
        ASN1Encodable[] values = signingCert.getAttributeValues();
        for (int i = 0; i < values.length; i++) {
          SigningCertificate sc = SigningCertificate.getInstance(values[i].toASN1Primitive());
          ESSCertID[] certs = sc.getCerts();
          for (int k = 0; k < certs.length; k++) {
            authCerts.add(certs[k].getIssuerSerial());
          }
        }
      }
    }
    return authCerts.equals(issuerSerials);
  }

  /**
   * @return
   * @throws TimeStampValidationException
   */
  private void getCertificateChains() throws TimeStampValidationException {
    //Map<X509Certificate, List<X509Certificate>> getCertificateChains() throws TimeStampValidationException {
    //Map<X509Certificate, List<X509Certificate>> chains = new HashMap<>();

    for (BigInteger serial : this.getSignersCertificates().keySet()) {
      X509Certificate cert = this.getSignersCertificates().get(serial).getX509Certificate();
      X509Certificate key = cert;
      //System.out.println("getCertificateChains: " + cert);
      List<X509Certificate> chain = new ArrayList<>();
      while (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
        X509Certificate ncert = this.certificates.get(cert.getIssuerX500Principal());
        if (ncert != null) {
          chain.add(ncert);
          cert = ncert;
        } else {
          chain.add(cert);
          break;
        }
      }
      this.chains.put(key, chain);
    }
    //return chains;
  }

  /**
   * signerInfos is a collection of per-signer information.  There MAY be any number of elements in
   * the collection, including zero. Since each signer can employ a different digital signature
   * technique, and future specifications could update the syntax, all implementations MUST
   * gracefully handle unimplemented versions of SignerInfo.  Further, since all implementations
   * will not support every possible signature algorithm, all implementations MUST gracefully handle
   * unimplemented signature algorithms when they are encountered.
   */
  private List<Object> getSignersIdentifiers() throws TimeStampValidationException {
    List<Object> signers = new ArrayList<>();

    Collection<SignerInformation> csi = this.getSignedData().getSignerInfos().getSigners();
    for (SignerInformation si : csi) {
      //If the SignerIdentifier is the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
      //the SignerIdentifier is subjectKeyIdentifier, then the version MUST be 3.
      // TODO: need an example to test handling subjectKeyIdentifier entries
      if (si.getVersion() == 1) {
        signers.add(si.getSID().getSerialNumber());
      } else if (si.getVersion() == 3) {
        signers.add(si.getSID().getSubjectKeyIdentifier());
      }
    }

    return signers;
  }

  /**
   * TODO: add a method to generate a certificate from byte array to crypto
   * eu.europa.futuretrust.protocol.utils Extracts certificate data from a CMS time stamp.
   * <p>
   * RFC 5652
   * <p>
   * It is intended that the set of certificates be sufficient to contain certification paths from a
   * recognized "root" or "top-level certification authority" to all of the signers in the
   * signerInfos field.
   * <p>
   * There may also be fewer certificates than necessary, if it is expected that recipients have an
   * alternate means of obtaining necessary certificates (e.g., from a previous set of
   * certificates). (NOT SUPPORTED at the moment.)
   */
  private void collectCertificateData() throws TimeStampValidationException {
    List<Object> signersSerials = this.getSignersIdentifiers();

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      CollectionStore store = (CollectionStore) this.signedData.getCertificates();
      Iterator it = store.iterator();
      while (it.hasNext()) {
        X509CertificateHolder holder = (X509CertificateHolder) it.next();
        X509Certificate cert = (X509Certificate)
            cf.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
        if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
          this.trustPoints.add(
              new String(Base64.getEncoder().encode(cert.getEncoded()))
          );
        }
        this.certificates.put(cert.getSubjectX500Principal(), cert);
        if (signersSerials.contains(cert.getSerialNumber())
            || signersSerials.contains(
            cert.getExtensionValue(X509Identifiers.id_ce_subjectKeyIdentifier.getId()))) {
          this.signersCertificates.put(cert.getSerialNumber(),
              new X509CertificateStatus(cert, false));
        }
      }
    } catch (Exception e) {
      //IOException, CertificateException
      throw new TimeStampValidationException(e.getMessage(), e);
    }
  }

  class X509CertificateStatus {

    private X509Certificate x509Certificate;
    private ValidationResult result;
    private boolean valid;

    public X509CertificateStatus(X509Certificate x509Certificate, boolean valid) {
      this.x509Certificate = x509Certificate;
      this.valid = valid;
    }

    public X509CertificateStatus(X509Certificate x509Certificate, boolean valid,
        ValidationResult result) {
      this(x509Certificate, valid);
      this.result = result;
    }

    public X509Certificate getX509Certificate() {
      return x509Certificate;
    }

    public ValidationResult getResult() {
      return result;
    }

    public boolean isValid() {
      return valid;
    }
  }
}
