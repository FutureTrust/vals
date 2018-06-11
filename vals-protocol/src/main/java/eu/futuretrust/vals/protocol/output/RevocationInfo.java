package eu.futuretrust.vals.protocol.output;

import eu.futuretrust.vals.protocol.enums.RevocationReason;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import java.util.Date;

public class RevocationInfo {

  private byte[] x509CertificateBase64;
  private Date revocationTime;
  private RevocationReason revocationReason;
  private byte[] revocationDataBase64;
  private ValidationObjectTypeId voType;


  public byte[] getX509CertificateBase64() {
    return x509CertificateBase64;
  }

  public void setX509CertificateBase64(byte[] x509CertificateBase64) {
    this.x509CertificateBase64 = x509CertificateBase64;
  }

  public Date getRevocationTime() {
    return revocationTime;
  }

  public void setRevocationTime(Date revocationTime) {
    this.revocationTime = revocationTime;
  }

  public RevocationReason getRevocationReason() {
    return revocationReason;
  }

  public void setRevocationReason(RevocationReason revocationReason) {
    this.revocationReason = revocationReason;
  }

  public ValidationObjectTypeId getVoType() {
    return voType;
  }

  public void setVoType(ValidationObjectTypeId voType) {
    this.voType = voType;
  }

  public byte[] getRevocationDataBase64() {
    return revocationDataBase64;
  }

  public void setRevocationDataBase64(byte[] revocationDataBase64) {
    this.revocationDataBase64 = revocationDataBase64;
  }
}
