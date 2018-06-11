package eu.futuretrust.vals.protocol.exceptions;


import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * A SignerIdentityException is a VerifyResponseException which asserts the occurence of an error
 * when attempting to return the Signer's identity in a VerifyResponse.
 */
public class SignerIdentityException extends VerifyResponseException {

  public SignerIdentityException(String message, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public SignerIdentityException(Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public SignerIdentityException(String message, Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }

}
