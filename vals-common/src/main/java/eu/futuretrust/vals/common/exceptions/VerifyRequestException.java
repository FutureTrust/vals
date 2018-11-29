package eu.futuretrust.vals.common.exceptions;

import eu.futuretrust.vals.common.enums.ResultMajor;
import eu.futuretrust.vals.common.enums.ResultMinor;

public class VerifyRequestException extends ResultException {

  public VerifyRequestException(String message, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(message, resultMajor, resultMinor);
  }

  public VerifyRequestException(Throwable cause, ResultMajor resultMajor, ResultMinor resultMinor) {
    super(cause, resultMajor, resultMinor);
  }

  public VerifyRequestException(String message, Throwable cause, ResultMajor resultMajor,
                                ResultMinor resultMinor) {
    super(message, cause, resultMajor, resultMinor);
  }
}