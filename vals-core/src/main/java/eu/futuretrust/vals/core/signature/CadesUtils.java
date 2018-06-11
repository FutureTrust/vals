package eu.futuretrust.vals.core.signature;

import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

public final class CadesUtils {

  private CadesUtils() {
  }

  public static boolean isAttachedSignature(CMSSignedData signedData) {
    return !signedData.isDetachedSignature();
  }

  public static boolean isDetachedSignature(CMSSignedData signedData) {
    return signedData.isDetachedSignature();
  }

  public static CMSSignedData getSignedData(byte[] cmsSignature) throws SignatureException {
    try {
      return new CMSSignedData(cmsSignature);
    } catch (CMSException e) {
      throw new SignatureException(e.getCause());
    }
  }

}
