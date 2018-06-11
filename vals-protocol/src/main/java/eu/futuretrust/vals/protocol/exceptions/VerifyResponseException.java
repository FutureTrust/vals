package eu.futuretrust.vals.protocol.exceptions;


import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * A VerifyResponseException is a CommonException which asserts the occurrence of an error when
 * trying to build a VerifyResponse
 */
public class VerifyResponseException extends ResultException {

  public VerifyResponseException(String message, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public VerifyResponseException(Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public VerifyResponseException(String message, Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}
