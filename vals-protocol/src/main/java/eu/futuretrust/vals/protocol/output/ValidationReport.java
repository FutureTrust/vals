package eu.futuretrust.vals.protocol.output;


import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.OptionalOutputsVerifyType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ResultType;

/**
 * A ValidationReport is a POJO which encapsulates the Result and the OptionalOutputs to return
 * after performing a validation
 */
public class ValidationReport {

  private ResultType result;
  private OptionalOutputsVerifyType optionalOutputs;

  public ValidationReport(ResultType result) {
    this.result = result;
  }

  public ResultType getResult() {
    return result;
  }

  public void setResult(ResultType result) {
    this.result = result;
  }

  public OptionalOutputsVerifyType getOptionalOutputs() {
    return optionalOutputs;
  }

  public void setOptionalOutputs(
      OptionalOutputsVerifyType optionalOutputs) {
    this.optionalOutputs = optionalOutputs;
  }
}
