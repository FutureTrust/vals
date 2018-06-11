package eu.futuretrust.vals.core.signature;

import eu.futuretrust.vals.core.enums.SignatureProperties;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public final class XadesUtils {

  private XadesUtils() {
  }

  public static boolean isReferenceEnveloped(Reference reference) {
    return isValidReference(reference) && reference.getURI().equals("");
  }

  public static boolean isReferenceEnveloping(Reference reference) {
    return isValidReference(reference) && reference.getURI().charAt(0) == '#';
  }

  public static boolean isReferenceDetached(Reference reference) {
    return isValidReference(reference) && !isReferenceEnveloped(reference)
        && !isReferenceEnveloping(reference);
  }

  public static boolean typeIsNotSignatureProperties(String type) {
    return !SignatureProperties.contains(type);
  }

  public static Document getDocument(byte[] xmlDocument) throws SignatureException {
    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      dbf.setNamespaceAware(true);
      DocumentBuilder db = dbf.newDocumentBuilder();
      return db.parse(new ByteArrayInputStream(xmlDocument));
    } catch (ParserConfigurationException | IOException | SAXException e) {
      throw new SignatureException(
          "The signature cannot be loaded as XML document : " + e.getMessage());
    }
  }

  public static List<XMLSignature> getXmlSignatures(Document xmlDocument)
      throws SignatureException {
    NodeList signatureElement = xmlDocument
        .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

    if (signatureElement == null) {
      throw new SignatureException(
          "Signature cannot be found in XML document (Signature element is missing)");
    }

    int signatureElementLength = signatureElement.getLength();
    if (signatureElementLength == 0) {
      throw new SignatureException(
          "No signature found in the document");
    }

    List<XMLSignature> signatures = new ArrayList<>();
    for (int i = 0; i < signatureElementLength; i++) {
      Element element = (Element) signatureElement.item(i);
      try {
        XMLSignature signature = new XMLSignature(element, "");
        signatures.add(signature);
      } catch (XMLSecurityException | NullPointerException e) {
        throw new SignatureException(
            "Signature at index " + i
                + " cannot be parsed (please check that the signature is well-formed) : " + e
                .getMessage());
      }
    }

    return signatures;
  }

  public static List<XMLSignature> getXmlSignatures(byte[] xmlDocument) throws SignatureException {
    try {
      Document doc = getDocument(xmlDocument);
      return getXmlSignatures(doc);
    } catch (SignatureException e) {
      throw new SignatureException(e.getCause());
    }
  }

  public static List<Manifest> getManifests(Document xmlDocument) {
    NodeList manifestElement = xmlDocument
        .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Manifest");

    if (manifestElement == null || manifestElement.getLength() == 0) {
      return new ArrayList<>();
    }

    List<Manifest> manifests = new ArrayList<>();
    int manifestElementLength = manifestElement.getLength();
    for (int i = 0; i < manifestElementLength; i++) {
      Element element = (Element) manifestElement.item(i);
      try {
        Manifest manifest = new Manifest(element, "");
        manifests.add(manifest);
      } catch (XMLSecurityException | NullPointerException ignored) {
        // if Manifest cannot be parsed just don't use it
      }
    }

    return manifests;
  }

  public static List<Manifest> getManifests(byte[] xmlDocument) throws SignatureException {
    Document doc = getDocument(xmlDocument);
    return getManifests(doc);
  }

  private static boolean isValidReference(Reference reference) {
    return reference != null && reference.getURI() != null;
  }

}
