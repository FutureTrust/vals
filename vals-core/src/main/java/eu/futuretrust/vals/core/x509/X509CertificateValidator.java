package eu.futuretrust.vals.core.x509;

import eu.futuretrust.vals.core.etsi.esi.ValidationResult;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.core.etsi.esi.exceptions.CertificateValidationException;
import eu.futuretrust.vals.core.helpers.ASN1Utils;
import eu.futuretrust.vals.core.helpers.CryptoUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * use -Djava.security.debug="certpath" in run configurations for detailed debug output
 */
public class X509CertificateValidator implements X509Validation {
  private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidator.class);
  // context-specific tag value for GeneralNames entry fullName
  private final static int CONTEXT_TAG_FULLNAME = 0;
  // revocation checks
  X509CVParameters params;
  private static X509CertificateValidator instance = null;

  private X509Certificate x509Cert, root;
  private List<X509Certificate> certPath;

  private X509CertificateValidator() {
  }

  public static X509CertificateValidator getInstance() {
    return instance == null ? new X509CertificateValidator() : instance;
  }

  public ValidationResult validate(X509AttributeCertificateHolder holder,
                                   Map<X500Name, X509Certificate> attributeAuthorities,
                                   X509CVParameters params) throws CertificateValidationException {
    if (!holder.isValidOn(new Date(System.currentTimeMillis())))
      return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.GENERIC,
        Collections.singletonList("Invalid Attribute Certificate."));

    ValidationResult ret;

    V2Form form = (V2Form) holder.toASN1Structure().getAcinfo().getIssuer().getIssuer();
    X500Name issuer = X500Name.getInstance(form.getIssuerName().getNames()[0].getName());

    X509Certificate attributeAuthority = attributeAuthorities.get(issuer);

    this.init(attributeAuthority, new ArrayList<>(), params);

    ret = this.validateCertificate(new Date(System.currentTimeMillis()));
    if (ret.getMainIndication() == MainIndication.TOTAL_PASSED) {
      JcaContentVerifierProviderBuilder builder = new JcaContentVerifierProviderBuilder();

      try {
        ContentVerifierProvider provider = builder.build(attributeAuthority);
        if (!holder.isSignatureValid(provider))
          return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.GENERIC,
            Collections.singletonList("Invalid Attribute Certificate."));
      } catch (Exception e) {
        //CertException, OperatorCreationException
        throw new CertificateValidationException(e.getMessage(), e);
      }

      // RFC 5755 - the keyUsage extension in the PKC MUST NOT explicitly indicate that the AC
      // issuer's public key cannot be used to validate a digital signature.
      // RFC 5280 (https://tools.ietf.org/html/rfc5280#section-4.2.1.3)
      if (!this.x509Cert.getKeyUsage()[0])
        return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.GENERIC,
          Collections.singletonList("Invalid Attribute Certificate."));

      // RFC - 5755: an AC issuer cannot be a CA as well.
      if (BasicConstraints.getInstance(
        this.getCertExtensionASN1Seq(this.x509Cert, X509Identifiers.basicConstraints.getId())
      ).isCA())
        return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.GENERIC,
          Collections.singletonList("Invalid Attribute certificate."));
    }

    return ret;
  }

  @Override
  public ValidationResult validate(X509Certificate x509Cert, X509CVParameters params)
    throws CertificateValidationException {
    this.init(x509Cert, new ArrayList<>(), params);

    return this.validateCertificate(new Date(System.currentTimeMillis()));
  }

  @Override
  public ValidationResult validate(X509Certificate x509Cert, List<X509Certificate> certPath,
                                   X509CVParameters params) throws CertificateValidationException {
    this.init(x509Cert, certPath, params);

    return this.validateCertificate(new Date(System.currentTimeMillis()));
  }

  @Override
  public ValidationResult validate(X509Certificate x509Cert, List<X509Certificate> certPath)
    throws CertificateValidationException {
    this.init(x509Cert, certPath, null);

    return this.validateCertificate(new Date(System.currentTimeMillis()));
  }

  public ValidationResult validate(X509Certificate x509Cert, List<X509Certificate> certPath, Date pastTime)
    throws CertificateValidationException {
    this.init(x509Cert, certPath, null);

    return this.validateCertificate(pastTime);
  }

  @Override
  public ValidationResult validate(X509Certificate x509Cert) throws CertificateValidationException {
    this.init(x509Cert, new ArrayList<>(), null);

    return this.validateCertificate(new Date(System.currentTimeMillis()));
  }

  private void init(X509Certificate x509Cert, List<X509Certificate> path, X509CVParameters params) {
    this.x509Cert = x509Cert;
    this.certPath = path;
    this.params = params;
  }

  public void setParams(X509CVParameters params) {
    this.params = params;
  }

  public void setCertPath(List<X509Certificate> certPath) {
    this.certPath = certPath;
  }

  /**
   * Assumption: path is ordered from end-entity to root CA.
   *
   * @param path
   * @return
   */
  public static boolean checkCertificationPathMembers(List<X509Certificate> path) {
    for (int i = path.size() - 1; i >= 1; i--) {
      X500Principal currSubject = path.get(i).getSubjectX500Principal();
      if (!currSubject.equals(path.get(i - 1).getIssuerX500Principal())) {
        return false;
      }
    }
    return true;
  }

  /**
   * Will we have a list of trust anchors?
   * <p>
   * Currently this method only get a single trust anchor. The anchor is extracted from certificate extensions or
   * from a certification path collected from the signature's KeyInfo element.
   *
   * @return
   */
  private Set<TrustAnchor> getTrustAnchors() {
    if (this.root == null && !this.certPath.isEmpty()) {
      this.root = this.getPathsRootCert(this.certPath);
    }
    TrustAnchor ta = new TrustAnchor(this.root, null);

    return Collections.singleton(ta);
  }

  /**
   * Given an end-entity certificate, finds the root certificate for
   * the end-entity certificate's certification path.
   * <p>
   * It also collects the certificates that constitute the certification path.
   * <p>
   * The assumption is that certificates in the certification path contain the
   * 'id-ad-caIssuers' extension. If not, a different approach needs to be used.
   * The alternatives to this method are currently limited to collecting the
   * certification path from the 'KeyInfo' entry in a XAdES signature file.
   * <p>
   * This seems to be possible with signing certificates. Not very common for SSL certificates.
   *
   * @param cert end-entity certificate
   */
  private void extensionsBasedInit(X509Certificate cert) throws CertificateValidationException {
    // build certification path
    this.certPath.add(cert);

    if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
      this.root = cert;
    } else {
      // get next cert from caIssuers
      if (this.isExtension(cert, X509Identifiers.id_pe_authorityInfoAccess.getId()) &&
        this.getAccessMethod(cert, X509ObjectIdentifiers.id_ad_caIssuers.getId()) != null) {
        try {
          this.extensionsBasedInit(this.getX509fromURL(
            this.getAccessMethod(cert, X509ObjectIdentifiers.id_ad_caIssuers.getId())));
        } catch (CertificateValidationException e) {
          throw new CertificateValidationException("Extension-based init failed: " + e.getMessage());
        }
      }
    }
  }

  public static X509Certificate getRootV3Extensions(X509Certificate cert) {
    return new X509CertificateValidator().getRootRecursively(cert);
  }

  public X509Certificate getRootRecursively(X509Certificate cert) {

    if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()))
      this.root = cert;
    else {
      try {
        // TODO: check the case of multiple instances of the id-ad-caIssuers accessMethod
        // An authorityInfoAccess extension may include multiple instances of the id-ad-caIssuers accessMethod.
        String issuer = this.getAccessMethod(cert, X509ObjectIdentifiers.id_ad_caIssuers.getId());
        if (this.isExtension(cert, X509Identifiers.id_pe_authorityInfoAccess.getId()) && issuer != null)
          this.getRootRecursively(this.getX509fromURL(issuer));
      } catch (CertificateValidationException e) {
        e.printStackTrace();
      }
    }

    return this.root;
  }

  /**
   * Retrieves a certificate file (DER format) from a given URL.
   *
   * @param fileURL location of the certificate file
   * @return an X509Certificate instance
   */
  private X509Certificate getX509fromURL(String fileURL) throws CertificateValidationException {
    try {
      URL url = new URL(fileURL);
      InputStream certStream = url.openStream();

      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);

      return cert;

    } catch (Exception ex) {
      if (ex instanceof CertificateException)
        throw new CertificateValidationException("Could not get certificate.", ex);
      else if (ex instanceof IOException)
        throw new CertificateValidationException("IO error retrieving certificate from URL: " + ex.getMessage());
      else
        throw new CertificateValidationException("Unknown exception: " + ex.getMessage());
    }
  }

  private ValidationResult checkValidity(X509Certificate certificate, Date inTime) {
    try {
      if(inTime == null) certificate.checkValidity();
      else certificate.checkValidity(inTime);

      return new ValidationResult(MainIndication.TOTAL_PASSED);
    } catch (Exception ex) {
      return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.OUT_OF_BOUNDS_NO_POE);
    }
  }

  /*private boolean checkCertSignature(X509Certificate toCheck, X509Certificate issuer) {
    try {
      return CryptoUtils.verifySignature(toCheck.getTBSCertificate(),
        toCheck.getSignature(), issuer, toCheck.getSigAlgName());
    } catch (CertificateEncodingException cee) {
      System.out.println("Encoding exception: " + cee.getMessage());
    }
    return false;
  }*/

  private int getExtensionCount(X509Certificate certificate) {
    return certificate.getCriticalExtensionOIDs().size() +
      certificate.getNonCriticalExtensionOIDs().size();
  }

  private void getOCSPResponder() {
    try {
      if (this.params.getOptions().contains(X509CVParameters.Option.OCSP_CHECK_CA)
        || this.params.getOptions().contains(X509CVParameters.Option.OCSP_CHECK_EE) &&
        this.isExtension(this.x509Cert, X509Identifiers.id_pe_authorityInfoAccess.getId()) &&
        this.getAccessMethod(this.x509Cert, X509ObjectIdentifiers.id_ad_ocsp.getId()) != null) {

        String ocspURIstr = this.getAccessMethod(this.x509Cert, X509ObjectIdentifiers.id_ad_ocsp.getId());
        if (ocspURIstr != null)
          logger.info(ocspURIstr);

        //pkixrc.setOcspResponder(new URI(ocspURIstr));
      }
    } catch (Exception cve) {
      cve.printStackTrace();
    }
  }

  /**
   * Assumption: path is ordered from end-entity to root CA.
   * <p>
   * Retrieves the root of a given certification path.
   * Checks the signature for each certificate along the path.
   *
   * @param path
   * @return
   */
  private X509Certificate getPathsRootCert(List<X509Certificate> path) {
    //X509Certificate root = null;

    for (X509Certificate cert : path) {
      if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()))
        return cert;
    }

    return null;

    /*if (path.size() == 1 &&
      path.get(0).getSubjectX500Principal().equals(path.get(0).getIssuerX500Principal())
      && this.checkCertSignature(path.get(0), path.get(0)))
      return path.get(0);

    for (int i = path.size() - 1; i >= 1; i--) {
      X500Principal currSubject = path.get(i).getSubjectX500Principal();
      if (currSubject.equals(path.get(i).getIssuerX500Principal()) &&
        this.checkCertSignature(path.get(i), path.get(i))) {
        root = path.get(i);
      }
      if (!currSubject.equals(path.get(i - 1).getIssuerX500Principal()) ||
        !this.checkCertSignature(path.get(i - 1), path.get(i))) {
        return null;
      }
    }*/
    //return root;
  }

  /**
   * 1. Obtain the CA root certificates and the certification path to be validated.
   * 2. Create a PKIXParameters with the trust anchors.
   * 3. Use a CertPathValidator to validate the certificate path.
   *
   * @return
   * @throws CertificateValidationException
   */
  private ValidationResult validateCertificate(Date inTime) throws CertificateValidationException {
    ValidationResult res = this.checkValidity(this.x509Cert, inTime);
    if (res.getMainIndication() == MainIndication.TOTAL_PASSED) {
      logger.info("X.509 certificate validity check passed. Proceed with validation.");

      if (this.certPath.size() == 0) {

        logger.info("No certification path provided. Attempting extension-based init.");
        if (this.isExtension(this.x509Cert, X509Identifiers.id_pe_authorityInfoAccess.getId()) &&
          this.getAccessMethod(this.x509Cert, X509ObjectIdentifiers.id_ad_caIssuers.getId()) != null) {
          logger.info("Extension 'id-ad-caIssuers' present. Proceed with extension-based init.");
          logger.info(String.format("Extension count: %d", this.getExtensionCount(this.x509Cert)));

          // initialize root certificate to use as TrustAnchor and collect a certification path
          this.extensionsBasedInit(this.x509Cert);
        }

        if (this.root == null) {
          logger.error("[Extension-based init failed. " +
            "Could not retrieve a root certificate. Provide a certification path.");
          return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.NO_CERTIFICATE_CHAIN_FOUND);
        }

      } else {
        logger.info("Certification path provided.");

        this.root = this.getPathsRootCert(this.certPath);
      }

      // certification path provided, means the path is invalid
      if (this.root == null)
        return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE,
          Collections.singletonList(this.certPath));

      return this.validateCertificationPath();
    }
    return res;
  }

  private X509CRL getX509CRLfromURL(String fileURL) {

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      if (fileURL != null) {
        URL oURL = new URL(fileURL);
        InputStream crlStream = oURL.openStream();
        X509CRL crl = (X509CRL) cf.generateCRL(crlStream);

        return crl;
      }
    } catch (Exception e) {
      //CertificateValidationException, MalformedURLException, IOException, CRLException
      e.printStackTrace();
    }
    return null;
  }

  /**
   * PKIXRevocationChecker uses OCSP by default and CRL as fallback, fallback
   * mechanism can be disabled.
   * <p>
   * EnuRevReqType = [ crlCheckEE | ocspCheckEE | bothCheck | eitherCheck | noCheck ]
   * [bothCheck|eitherCheck] = {crlCheckEE = true && ocspCheckEE = true} fall to OCSP
   * CertificateReqType = [ signerOnly | fullPath ]
   *
   * @param params
   * @param pkixrc
   * @return
   * @throws CertificateValidationException
   */
  private PKIXBuilderParameters setRevocationParams(
    PKIXBuilderParameters params,
    PKIXRevocationChecker pkixrc, boolean crl) throws CertificateValidationException {

    HashSet<PKIXRevocationChecker.Option> revOptions = new HashSet<>();

    if (!this.params.getOptions().contains(X509CVParameters.Option.CRL_CHECK_CA)
      && !this.params.getOptions().contains(X509CVParameters.Option.OCSP_CHECK_CA)) {
      // noCheck for CA means only end-entity certificates are checked
      revOptions.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
    }

    if (crl) revOptions.add(PKIXRevocationChecker.Option.PREFER_CRLS);

    // we do not want a fallback mechanism
    // only the chosen mechanism is used
    revOptions.add(PKIXRevocationChecker.Option.NO_FALLBACK);

    pkixrc.setOptions(Collections.unmodifiableSet(revOptions));
    // supersedes isRevocationEnabled.
    params.addCertPathChecker(pkixrc);

    return params;
  }


  private List<X509Certificate> getCertPath() {
    List<X509Certificate> path = new ArrayList<>(this.certPath);

    if (this.params != null
      && (this.params.getOptions().contains(X509CVParameters.Option.CRL_CHECK_CA)
      || this.params.getOptions().contains(X509CVParameters.Option.OCSP_CHECK_CA)
      || this.params.getOptions().contains(X509CVParameters.Option.BOTH_CHECK_CA))
      && path.size() > 0 && this.root != null) {
      // returns UNDETERMINED_REVOCATION_STATUS if root is present, whether the path is valid or not
      // need to remove the root (Trust Anchor? Trust Point?), otherwise there is no OCSP responder
      // or CRL distribution point on the first certificate to be checked
      path.remove(this.root);
    }

    path = CryptoUtils.sortX509Certlist(path);

    return path;
  }

  private boolean processX509CVParams() {
    boolean ret = false;
    if (this.params != null) {
      if (this.params.getOptions().contains(X509CVParameters.Option.BOTH_CHECK_EE) ||
        this.params.getOptions().contains(X509CVParameters.Option.BOTH_CHECK_CA)) {
        ret = true;
      }
    } else {
      Set<X509CVParameters.Option> options = new HashSet<>();
      options.add(X509CVParameters.Option.CRL_CHECK_EE);
      options.add(X509CVParameters.Option.CRL_CHECK_CA);
      this.params = new X509CVParameters(options);
    }

    return ret;
  }

  /**
   * noCheck = {crlCheckEE = false, ocspCheckEE = false}
   *
   * @return
   * @throws CertificateValidationException
   */
  private ValidationResult validateCertificationPath() throws CertificateValidationException {
    Set<TrustAnchor> tas = this.getTrustAnchors();
    boolean bothCheck = this.processX509CVParams();

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      CertPath cp = cf.generateCertPath(this.getCertPath());

      CertPathValidator cpv = CertPathValidator.getInstance("PKIX");

      PKIXBuilderParameters params = new PKIXBuilderParameters(tas, new X509CertSelector());

      if (this.params != null) {
        if (bothCheck) {
          PKIXBuilderParameters bcheck = (PKIXBuilderParameters) params.clone();

          this.setRevocationParams(bcheck, (PKIXRevocationChecker) cpv.getRevocationChecker(), true);
          this.setRevocationParams(params, (PKIXRevocationChecker) cpv.getRevocationChecker(), false);

          cpv.validate(cp, bcheck);

        } else {
          if (this.params.getOptions().contains(X509CVParameters.Option.CRL_CHECK_CA)
            || this.params.getOptions().contains(X509CVParameters.Option.CRL_CHECK_EE)) {
            this.setRevocationParams(params, (PKIXRevocationChecker) cpv.getRevocationChecker(), true);
          } else
            this.setRevocationParams(params, (PKIXRevocationChecker) cpv.getRevocationChecker(), false);
        }
      }

      cpv.validate(cp, params);

      return new ValidationResult(MainIndication.TOTAL_PASSED);

    } catch (Exception ex) {
      if (ex instanceof CertPathValidatorException) {
        ValidationResult res;
        if (((CertPathValidatorException) ex).getReason().equals(CertPathValidatorException.BasicReason.REVOKED)) {
          res = new ValidationResult(MainIndication.TOTAL_FAILED, SubIndication.REVOKED,
            Arrays.asList(((CertPathValidatorException) ex).getCertPath(), ex.getMessage()));
        } else {
          CertPath cp = ((CertPathValidatorException) ex).getCertPath();
          res = new ValidationResult(MainIndication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE,
            Arrays.asList(((CertPathValidatorException) ex).getReason(), (cp != null ? cp : ex.getMessage())));
        }
        return res;
      } else
        return new ValidationResult(MainIndication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE,
          Arrays.asList(ex.getMessage(), ex));
    }
  }

  /**
   * id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
   * <p>
   * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
   * <p>
   * DistributionPoint ::= SEQUENCE {
   * distributionPoint       [0]     DistributionPointName OPTIONAL,
   * reasons                 [1]     ReasonFlags OPTIONAL,
   * cRLIssuer               [2]     GeneralNames OPTIONAL }
   * <p>
   * DistributionPointName ::= CHOICE {
   * fullName                [0]     GeneralNames,
   * nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
   *
   * @return
   * @throws CertificateValidationException
   */

  private String getCRLURI(X509Certificate cert) throws CertificateValidationException {
    ASN1Sequence seq =
      this.getCertExtensionASN1Seq(cert, X509Identifiers.id_ce_cRLDistributionPoints.getId());
    CRLDistPoint crldp = CRLDistPoint.getInstance(seq);

    for (DistributionPoint dp : crldp.getDistributionPoints()) {
      ASN1TaggedObject taggedObject = (ASN1TaggedObject) dp.getDistributionPoint().toASN1Primitive();
      if (taggedObject.getTagNo() == CONTEXT_TAG_FULLNAME) {
        GeneralName[] gns = GeneralNames.getInstance(taggedObject, false).getNames();
        for (GeneralName gn : gns) {
          return gn.getName().toString();
        }
      }
    }
    return null;
  }


  /**
   * RFC5280 (https://www.ietf.org/rfc/rfc5280.txt)
   * <p>
   * The object identifiers associated with the private extensions are defined
   * under the arc id-pe within the arc id-pkix.
   * <p>
   * id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
   * <p>
   * AuthorityInfoAccessSyntax  ::=
   * SEQUENCE SIZE (1..MAX) OF AccessDescription
   * <p>
   * AccessDescription  ::=  SEQUENCE {
   * accessMethod          OBJECT IDENTIFIER,
   * accessLocation        GeneralName  }
   * <p>
   * This profile defines two accessMethod OIDs: id-ad-caIssuers and id-ad-ocsp.
   *
   * @param cert
   * @param oid
   * @return
   * @throws CertificateValidationException
   */
  private String getAccessMethod(X509Certificate cert, String oid) throws CertificateValidationException {
    ASN1Sequence seq =
      this.getCertExtensionASN1Seq(cert, X509Identifiers.id_pe_authorityInfoAccess.getId());
    AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(seq);
    for (AccessDescription ad : aia.getAccessDescriptions()) {
      if (ad.getAccessMethod().getId().equals(oid)) {
        return ad.getAccessLocation().getName().toString();
      }
    }
    return null;
  }

  private boolean isExtension(X509Certificate cert, String oid) {
    return cert.getExtensionValue(oid) != null;
  }

  private ASN1Sequence getCertExtensionASN1Seq(X509Certificate cert, String oid)
    throws CertificateValidationException {
    try {
      return ASN1Utils.byteArrayToASN1Seq(cert.getExtensionValue(oid));
    } catch (IOException ioe) {
      throw new CertificateValidationException("IO error: " + ioe.getMessage());
    }
  }
}
