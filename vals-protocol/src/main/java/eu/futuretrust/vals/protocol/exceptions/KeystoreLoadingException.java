package eu.futuretrust.vals.protocol.exceptions;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * A KeyStoreException is an IndividualReportException which asserts that there was a problem in the
 * load of a keystore during validation, in order to build an IndividualReport
 */
public class KeystoreLoadingException extends IndividualReportException {

  public KeystoreLoadingException(String message, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public KeystoreLoadingException(Throwable cause, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public KeystoreLoadingException(String message, Throwable cause, ResultMajor resultMajor,
                                  ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}
