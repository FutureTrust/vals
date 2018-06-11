package eu.futuretrust.vals.protocol.output;

public class DigestAlgoAndValue {

  private String digestAlgo;
  private byte[] value;

  public String getDigestAlgo() {
    return digestAlgo;
  }

  public void setDigestAlgo(String digestAlgo) {
    this.digestAlgo = digestAlgo;
  }

  public byte[] getValue() {
    return value;
  }

  public void setValue(byte[] value) {
    this.value = value;
  }
}
