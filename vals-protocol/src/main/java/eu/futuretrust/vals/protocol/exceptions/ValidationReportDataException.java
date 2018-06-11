package eu.futuretrust.vals.protocol.exceptions;


import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * A ValidationReportDataException is an IndividualReportException which asserts the occurrence of a
 * problem when attempting to build an associated Validation Report Data element for the
 * IndividualReport
 */
public class ValidationReportDataException extends IndividualReportException {

  public ValidationReportDataException(String message, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public ValidationReportDataException(Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public ValidationReportDataException(String message, Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}