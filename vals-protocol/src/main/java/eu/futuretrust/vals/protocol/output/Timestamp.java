package eu.futuretrust.vals.protocol.output;


import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.TimeStampValidityType;
import java.util.Date;
import java.util.List;

public class Timestamp {

  private final byte[] base64;
  private final TimeStampValidityType validity;
  private final List<byte[]> referencedObjectsByBase64;
  private final List<DigestAlgoAndValue> referencedObjectsByHash;
  private final Date poeTime;


  public Timestamp(final byte[] base64, final TimeStampValidityType validity,
      List<byte[]> referencedObjects, List<DigestAlgoAndValue> referencedObjectsByHash,
      Date poeTime) {
    this.base64 = base64;
    this.validity = validity;
    this.referencedObjectsByBase64 = referencedObjects;
    this.referencedObjectsByHash = referencedObjectsByHash;
    this.poeTime = poeTime;
  }

  public byte[] getBase64() {
    return base64;
  }

  public TimeStampValidityType getValidity() {
    return validity;
  }

  public List<byte[]> getReferencedObjectsByBase64() {
    return referencedObjectsByBase64;
  }

  public List<DigestAlgoAndValue> getReferencedObjectsByHash() {
    return referencedObjectsByHash;
  }

  public Date getPoeTime() {
    return poeTime;
  }

}
