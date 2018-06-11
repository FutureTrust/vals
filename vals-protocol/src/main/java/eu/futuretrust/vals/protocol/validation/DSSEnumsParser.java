package eu.futuretrust.vals.protocol.validation;

import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;

public final class DSSEnumsParser {

  private DSSEnumsParser() {
  }

  public static MainIndication parseMainIndication(Indication indication)
      throws DSSParserException {
    if (indication == null) {
      throw new DSSParserException(
          "No signature found",
          ResultMajor.REQUESTER_ERROR, ResultMinor.GENERAL_ERROR);
    }
    switch (indication) {
      case FAILED:
      case TOTAL_FAILED:
        return MainIndication.TOTAL_FAILED;
      case PASSED:
      case TOTAL_PASSED:
        return MainIndication.TOTAL_PASSED;
      case INDETERMINATE:
        return MainIndication.INDETERMINATE;
      default:
        throw new DSSParserException(
            "Unable to determine the main indication, current value is \"" + indication + "\"",
            ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
  }

  public static SubIndication parseSubIndication(
      eu.europa.esig.dss.validation.policy.rules.SubIndication subIndication)
      throws DSSParserException {
    if (subIndication == null) {
      return null;
    }
    switch (subIndication) {
      case NO_POE:
        return SubIndication.NO_POE;
      case EXPIRED:
        return SubIndication.EXPIRED;
      case REVOKED:
        return SubIndication.REVOKED;
      case TRY_LATER:
        return SubIndication.TRY_LATER;
      case HASH_FAILURE:
        return SubIndication.HASH_FAILURE;
      case NOT_YET_VALID:
        return SubIndication.NOT_YET_VALID;
      case FORMAT_FAILURE:
        return SubIndication.FORMAT_FAILURE;
      case REVOKED_NO_POE:
        return SubIndication.REVOKED_NO_POE;
      case REVOKED_CA_NO_POE:
        return SubIndication.REVOKED_CA_NO_POE;
      case SIG_CRYPTO_FAILURE:
        return SubIndication.SIG_CRYPTO_FAILURE;
      case OUT_OF_BOUNDS_NO_POE:
        return SubIndication.OUT_OF_BOUNDS_NO_POE;
      case SIGNED_DATA_NOT_FOUND:
        return SubIndication.SIGNED_DATA_NOT_FOUND;
      case POLICY_PROCESSING_ERROR:
        return SubIndication.POLICY_PROCESSING_ERROR;
      case SIG_CONSTRAINTS_FAILURE:
        return SubIndication.SIG_CONSTRAINTS_FAILURE;
      case TIMESTAMP_ORDER_FAILURE:
        return SubIndication.TIMESTAMP_ORDER_FAILURE;
      case CHAIN_CONSTRAINTS_FAILURE:
        return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
      case CRYPTO_CONSTRAINTS_FAILURE:
        return SubIndication.CRYPTO_CONSTRAINTS_FAILURE;
      case NO_CERTIFICATE_CHAIN_FOUND:
        return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
      case NO_SIGNING_CERTIFICATE_FOUND:
        return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
      case SIGNATURE_POLICY_NOT_AVAILABLE:
        return SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE;
      case CERTIFICATE_CHAIN_GENERAL_FAILURE:
        return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
      case CRYPTO_CONSTRAINTS_FAILURE_NO_POE:
        return SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
      default:
        throw new DSSParserException(
            "Unable to determine the main indication, current value is \"" + subIndication + "\"",
            ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
  }

}
