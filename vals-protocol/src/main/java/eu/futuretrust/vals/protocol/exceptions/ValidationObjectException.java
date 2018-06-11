package eu.futuretrust.vals.protocol.exceptions;


import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * A ValidationObjectException is an IndividualReportException which asserts the occurrence of a
 * problem while attempting to build an IndividualReport element.
 */
public class ValidationObjectException extends IndividualReportException {

  public ValidationObjectException(String message, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public ValidationObjectException(Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public ValidationObjectException(String message, Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}