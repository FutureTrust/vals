package eu.futuretrust.vals.protocol.validation.validity;


import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignatureValidityType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.VerificationResultType;

/**
 * A DSSSignatureValidityParser is an object which proposes to parse the
 * SignatureValidity from a boolean value
 */
public class DSSSignatureValidityParser {

  private SignatureValidityType signatureValidityType;
  private boolean valid;

  public DSSSignatureValidityParser(boolean valid){
    this.valid = valid;
    signatureValidityType = new SignatureValidityType();
  }

  public SignatureValidityType getSignatureValidityType() {
    VerificationResultType sigMathOk = new VerificationResultType();
    if (valid) {
      sigMathOk.setResultMajor(MainIndication.TOTAL_PASSED.getURI());
    } else {
      sigMathOk.setResultMajor(MainIndication.TOTAL_FAILED.getURI());
    }
    signatureValidityType.setSigMathOK(sigMathOk);
    return signatureValidityType;
  }
}
