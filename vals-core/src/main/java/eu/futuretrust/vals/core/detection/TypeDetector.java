package eu.futuretrust.vals.core.detection;

import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.CadesUtils;
import eu.futuretrust.vals.core.signature.XadesUtils;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import java.util.Optional;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cms.CMSSignedData;

public final class TypeDetector {

  private TypeDetector() {
  }

  public static SignedObjectType detect(XMLSignature xmlSignature)
      throws SignatureException {
    if (xmlSignature == null) {
      throw new SignatureException("XMLSignature cannot be null");
    }
    if (xmlSignature.getSignedInfo() == null || xmlSignature.getSignedInfo().getLength() == 0) {
      throw new SignatureException("Cannot find Signed info element");
    }

    TypeInfo typeInfo = findTypeInfo(xmlSignature);

    return getSignedObjectType(SignedObjectFormat.XML, typeInfo.isEnveloped(),
        typeInfo.isEnveloping(),
        typeInfo.isDetached());
  }

  private static TypeInfo findTypeInfo(XMLSignature xmlSignature) throws SignatureException {
    TypeInfo typeInfo = new TypeInfo();

    int signedInfoLength = xmlSignature.getSignedInfo().getLength();
    for (int i = 0; i < signedInfoLength; i++) {
      Reference reference;

      try {
        reference = xmlSignature.getSignedInfo().item(i);
      } catch (XMLSecurityException e) {
        throw new SignatureException(
            "Reference at index " + i + " in the signature could not be analyzed : " + e
                .getMessage());
      }

      if (isValidReference(reference)) {
        if (XadesUtils.isReferenceEnveloped(reference)) {
          typeInfo.setEnveloped(true);
        } else if (XadesUtils.isReferenceEnveloping(reference)) {
          // if enveloping reference is a Signature Properties then ignore it
          if (XadesUtils.typeIsNotSignatureProperties(reference.getType())) {
            typeInfo.setEnveloping(true);
          }
        } else {
          typeInfo.setDetached(true);
        }
      }
    }

    return typeInfo;
  }

  public static SignedObjectType detect(CMSSignedData cmsSignature)
      throws SignatureException {
    if (cmsSignature == null) {
      throw new SignatureException("CMSSignedData cannot be null");
    }
    boolean isAttached = CadesUtils.isAttachedSignature(cmsSignature);
    boolean isDetached = CadesUtils.isDetachedSignature(cmsSignature);

    return getSignedObjectType(SignedObjectFormat.PKCS7, false, isAttached, isDetached);
  }

  private static SignedObjectType getSignedObjectType(SignedObjectFormat signatureFormat,
      boolean isEnveloped, boolean isEnveloping, boolean isDetached) throws SignatureException {
    Optional<SignedObjectType> optionalSignedObjectType = SignedObjectType
        .fromBooleans(signatureFormat, isEnveloped, isEnveloping, isDetached);
    return optionalSignedObjectType.orElseThrow(() -> new SignatureException(
        "The signature type cannot be detected or is not a valid type"));
  }

  private static boolean isValidReference(Reference reference) {
    return reference != null && reference.getURI() != null;
  }

  private static class TypeInfo {

    private boolean enveloped = false;
    private boolean enveloping = false;
    private boolean detached = false;

    public boolean isEnveloped() {
      return enveloped;
    }

    public void setEnveloped(boolean enveloped) {
      this.enveloped = enveloped;
    }

    public boolean isEnveloping() {
      return enveloping;
    }

    public void setEnveloping(boolean enveloping) {
      this.enveloping = enveloping;
    }

    public boolean isDetached() {
      return detached;
    }

    public void setDetached(boolean detached) {
      this.detached = detached;
    }
  }

}
