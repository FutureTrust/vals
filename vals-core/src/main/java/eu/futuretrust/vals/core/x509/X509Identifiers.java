package eu.futuretrust.vals.core.x509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

public interface X509Identifiers {
  ASN1ObjectIdentifier basicConstraints = (new ASN1ObjectIdentifier("2.5.29.19")).intern(); //NOSONAR
  ASN1ObjectIdentifier id_ce_cRLDistributionPoints = X509ObjectIdentifiers.id_ce.branch("31").intern();
  ASN1ObjectIdentifier id_pe_authorityInfoAccess = X509ObjectIdentifiers.id_pe.branch("1").intern();
  ASN1ObjectIdentifier id_ce_subjectKeyIdentifier = X509ObjectIdentifiers.id_ce.branch("14").intern();
}
