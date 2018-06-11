package eu.futuretrust.vals.protocol.exceptions;


import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * An IndividualReportException is a VerifyResponseException which asserts a problem in the building
 * of an IndividualReport element, which is part of a VerifyResponse
 */
public class IndividualReportException extends VerifyResponseException {

  public IndividualReportException(String message, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public IndividualReportException(Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public IndividualReportException(String message, Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}
