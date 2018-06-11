package eu.futuretrust.vals.core.helpers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

/**
 * Created by rochafr on 09/08/2017.
 */
public final class ASN1Utils {

  private ASN1Utils() {
  }

  /**
   * Converts a byte array into an ASN1Sequence
   *
   * @param in
   * @return
   */
  public static ASN1Sequence byteArrayToASN1Seq(byte[] in) throws IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(in);
    ASN1InputStream asnIn = new ASN1InputStream(bais);

    DEROctetString oct = (DEROctetString) asnIn.readObject();
    bais = new ByteArrayInputStream(oct.getOctets());
    asnIn = new ASN1InputStream(bais);
    ASN1Sequence seq = (ASN1Sequence) asnIn.readObject();
    bais.close();
    asnIn.close();

    return seq;
  }
}
