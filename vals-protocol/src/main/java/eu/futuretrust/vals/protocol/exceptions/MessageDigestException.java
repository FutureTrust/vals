package eu.futuretrust.vals.protocol.exceptions;


import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * A MessageDigestException is an IndividualReportException which asserts that there was an error
 * when digesting bytes in order to build an IndividualReport element.
 */
public class MessageDigestException extends IndividualReportException {

  public MessageDigestException(String message, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public MessageDigestException(Throwable cause, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public MessageDigestException(String message, Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}