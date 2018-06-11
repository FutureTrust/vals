package eu.futuretrust.vals.protocol.output;


import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;

public class ResultIndication {

  private MainIndication mainIndication;
  private SubIndication subIndication;

  public ResultIndication(MainIndication mainIndication,
      SubIndication subIndication) {
    this.mainIndication = mainIndication;
    this.subIndication = subIndication;
  }

  public MainIndication getMainIndication() {
    return mainIndication;
  }

  public void setMainIndication(MainIndication mainIndication) {
    this.mainIndication = mainIndication;
  }

  public SubIndication getSubIndication() {
    return subIndication;
  }

  public void setSubIndication(SubIndication subIndication) {
    this.subIndication = subIndication;
  }
}
