package eu.futuretrust.vals.protocol.exceptions;


import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * DSSParserException is an IndividualReportException which asserts a problem in the parsing of the
 * Reports returned by DSS after a validation.
 */
public class DSSParserException extends IndividualReportException {

  public DSSParserException(String message, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public DSSParserException(Throwable cause, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public DSSParserException(String message, Throwable cause, ResultMajor resultMajor,
      ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}
