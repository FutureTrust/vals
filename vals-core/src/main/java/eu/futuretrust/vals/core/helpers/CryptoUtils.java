package eu.futuretrust.vals.core.helpers;

import eu.futuretrust.vals.core.detection.FormatDetector;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.helpers.exceptions.ReferenceException;
import eu.futuretrust.vals.core.signature.exceptions.FormatException;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.CertIDTypeV2;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.asn1.x509.X509AttributeIdentifiers;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaAttributeCertificateIssuer;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class CryptoUtils {

  private CryptoUtils() {
  }

  /**
   * Generates an attribute certificate to test certified roles
   *
   * @param inIssuer issuer certificate
   * @param inHolder holder certificate
   * @param inKey signing key
   * @param roleAuthority authority under which the role has meaning
   * @param roleName designation/description of the role
   * @param durationDays duration of the validity period for the certificate
   */
  public static void generateAttributeCertificate(InputStream inIssuer, InputStream inHolder,
      FileReader inKey,
      String roleAuthority, String roleName, long durationDays)
      throws CertificateException {
    X509Certificate issuer, holder;

    // get the X509 certs for issuer and holder
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      issuer = (X509Certificate) cf.generateCertificate(inIssuer);
      holder = (X509Certificate) cf.generateCertificate(inHolder);
    } catch (CertificateException ce) {
      throw new CertificateException(ce);
    }

    if (issuer == null || holder == null) {
      throw new CertificateException("Invalid issuer or holder certificate.");
    }

    X509CertificateHolder certHolder = new X509CertificateHolder(
        Certificate.getInstance(holder.getEncoded()));

    // initialize attribute cert holder and builder
    AttributeCertificateHolder attrCertHolder = new AttributeCertificateHolder(certHolder);
    X509v2AttributeCertificateBuilder builder = new X509v2AttributeCertificateBuilder(
        attrCertHolder,
        new JcaAttributeCertificateIssuer(issuer),
        new BigInteger("1234567890"),
        new Date(System.currentTimeMillis()),
        new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(durationDays))
    );

    try {
      PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) new PEMParser(inKey).readObject();
      RSAPrivateCrtKeyParameters params = (RSAPrivateCrtKeyParameters) PrivateKeyFactory
          .createKey(privateKeyInfo);
      RSAPrivateKey privateKey = new RSAPrivateKey(
          params.getModulus(),
          params.getPublicExponent(),
          params.getExponent(),
          params.getP(),
          params.getQ(),
          params.getDP(),
          params.getDQ(),
          params.getQInv()
      );

      PrivateKey pk =
          KeyFactory.getInstance("RSA").generatePrivate(
              new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent()));

      // use holder signature algorithm, should be RSA with SHA-256
      DefaultAlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();
      String algName = nameFinder.getAlgorithmName(certHolder.getSignatureAlgorithm());
      ContentSigner contentSigner = new JcaContentSignerBuilder(algName).build(pk);

      // populate the RoleSyntax members
      GeneralNamesBuilder gnBuilder = new GeneralNamesBuilder();
      gnBuilder.addName(new GeneralName(6, new DERIA5String(roleAuthority)));
      GeneralNames gNames = gnBuilder.build();

      RoleSyntax roleSyntax = new RoleSyntax(gNames,
          new GeneralName(6, new DERIA5String(roleName)));
      builder.addAttribute(X509AttributeIdentifiers.id_at_role,
          new DERSequence(roleSyntax.toASN1Primitive()));

      X509AttributeCertificateHolder attributeCertificateHolder = builder.build(contentSigner);

    } catch (IOException e) {
      throw new CertificateException("Cannot read private key info.", e);
    } catch (NoSuchAlgorithmException nsae) {
      throw new CertificateException("No such algorithm.", nsae);
    } catch (InvalidKeySpecException spec) {
      throw new CertificateException("Invalid private key spec.", spec);
    } catch (OperatorCreationException op) {
      throw new CertificateException("Could not create content signer.", op);
    }
  }

  /**
   * Computes the message digest of {@code data} using algorithm {@code algorithmURI}.
   *
   * @param data array of bytes to be hashed
   * @param algorithmURI unique URI value identifying a message digest algorithm
   * @return the message digest of {@code data} using algorithm {@code algorithmURI}
   */
  public static byte[] digestXmlAlgURI(byte[] data, String algorithmURI)
      throws NoSuchAlgorithmException {
    try {
      MessageDigest md = MessageDigest.getInstance(JCEMapper.translateURItoJCEID(algorithmURI));
      return md.digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw e;
    }
  }

  /**
   * Computes the message digest of {@code data} using the algorithm {@code oid}
   *
   * @param data array of bytes to digest
   * @param oid OID of the digest algorithm to use
   * @return the message digest of {@code data} using algorithm {@code oid}
   */
  public static byte[] digestAlgOID(byte[] data, String oid) throws NoSuchAlgorithmException {
    try {
      MessageDigest md = MessageDigest.getInstance(oid);
      return md.digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new NoSuchAlgorithmException(e.getMessage(), e);
    }
  }

  /**
   * Creates an X.509 certificate from a base64 array of bytes
   *
   * @param base64 X.509 certificate encoded as an array of bytes (base64-encoded)
   * @return an X.509 certificate instance generated from {@code base64}
   */
  public static X509Certificate base64toX509Certificate(byte[] base64) throws CertificateException {
    byte[] certBytes = Base64.getDecoder().decode(new String(base64).trim());
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certBytes));
  }

  /**
   * Generates an X.509 CRL from a base64 array of bytes
   *
   * @param base64 X.509 CRL encoded in an array of bytes (base64-encoded)
   * @return an X.509 CRL instance generated from {@code base64}
   */
  public static X509CRL base64ToX509CRL(byte[] base64) throws CertificateException, CRLException {
    byte[] crlBytes = Base64.getDecoder().decode(new String(base64).trim());
    return (X509CRL)
        CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(crlBytes));
  }

  /**
   * Retrieves the IssuerSerial from a CertIDTypeV2 instance
   *
   * @param certID CertIDTypeV2 instance from which to extract the IssuerSerial
   * @return an IssuerSerial instance
   */
  public static IssuerSerial getCertIDIssuerSerial(CertIDTypeV2 certID) throws IOException {
    IssuerSerial is;

    try {
      byte[] serial = Base64.getDecoder()
          .decode(new String(certID.getIssuerSerialV2()).trim().getBytes());
      is = IssuerSerial.getInstance(ASN1Primitive.fromByteArray(serial));
    } catch (IOException ioe) {
      throw ioe;
    }

    return is;
  }

  public static boolean verifySignature(byte[] data, byte[] signature, X509Certificate certificate,
      String alg)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    try {
      Signature sig = Signature.getInstance(alg);
      sig.initVerify(certificate.getPublicKey());
      sig.update(data);
      return sig.verify(signature);
    } catch (Exception e) {
      throw e;
    }
  }

  /**
   * Sorts a list of X.509 certificates using the order end-entity->root CA Note: Used as a quick
   * fix for the unpredictability of SD-DSS
   *
   * @param in unordered list of certificates
   * @return ordered list of certificates
   */
  public static List<X509Certificate> sortX509Certlist(List<X509Certificate> in) {
    in.sort(((o1, o2) -> {
      if (o1.getIssuerX500Principal().equals(o2.getSubjectX500Principal())) {
        return -1;
      } else if (o1.getSubjectX500Principal().equals(o2.getIssuerX500Principal())) {
        return 1;
      } else //if(o1.getSubjectX500Principal().equals(o2.getIssuerX500Principal()))
      {
        return 0;
      }
    }));

    return in;
  }

  public static XMLSignatureInput transform(Reference reference, byte[] document)
      throws XMLSecurityException {
    if (reference == null) {
      throw new NullPointerException("Reference is null");
    }
    if (document == null) {
      return null;
    }

    XMLSignatureInput currentDocument = new XMLSignatureInput(document);

    SignedObjectFormat format;
    try {
      format = FormatDetector.detect(document);
    } catch (FormatException e) {
      return currentDocument;
    }

    // transformation can only be applied to XML document
    if (format != SignedObjectFormat.XML) {
      return currentDocument;
    }

    Transforms transforms = reference.getTransforms();
    if (transforms != null) {
      return transforms.performTransforms(currentDocument);
    }
    return currentDocument;
  }

  public static byte[] computeDigest(Reference reference, XMLSignatureInput currentDocument)
      throws NoSuchAlgorithmException, XMLSignatureException, IOException, CanonicalizationException, ReferenceException {
    if (reference == null) {
      throw new NullPointerException("Reference is null");
    }
    if (currentDocument == null) {
      return null;
    }

    return MessageDigest
        .getInstance(reference.getMessageDigestAlgorithm().getJCEAlgorithmString())
        .digest(currentDocument.getBytes());
  }

  public static boolean equals(byte[] value1, byte[] value2) {
    return Arrays.equals(value1, value2);
  }
}
