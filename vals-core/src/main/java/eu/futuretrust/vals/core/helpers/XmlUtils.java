package eu.futuretrust.vals.core.helpers;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;
import java.util.Stack;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Utility class for dealing with XML DOM elements.
 *
 * @author Mikkel Heisterberg, lekkim@lsdoc.org
 */
public final class XmlUtils {

  private XmlUtils() {
  }

  private static final String XMLNAMESPACE = "xmlns";

  /**
   * Get all prefixes defined, up to the root, for a namespace URI.
   */
  public static void getPrefixesRecursive(Node element, String namespaceUri,
      List<String> prefixes) {
    getPrefixes(element, namespaceUri, prefixes);
    Node parent = element.getParentNode();
    getPrefixesRecursive(parent, namespaceUri, prefixes);
  }

  /**
   * Get all prefixes defined on this element for the specified namespace.
   */
  public static void getPrefixes(Node element, String namespaceUri, List<String> prefixes) {
    NamedNodeMap atts = element.getAttributes();
    for (int i = 0; i < atts.getLength(); i++) {
      Node node = atts.item(i);
      String name = node.getNodeName();
      if (namespaceUri.equals(node.getNodeValue())
          && (name != null && (XMLNAMESPACE.equals(name) || name.startsWith(XMLNAMESPACE + ":")))) {
        prefixes.add(node.getPrefix());
      }
    }
  }

  public static Optional<NodeList> evaluateXPath(byte[] document, String expression) {
    return evaluateXPath(new ByteArrayInputStream(document), expression);
  }

  public static Optional<NodeList> evaluateXPath(InputStream document, String expression) {
    try {
      DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
      DocumentBuilder b = f.newDocumentBuilder();
      Document d = b.parse(document);
      d.getDocumentElement().normalize();

      XPath xPath = XPathFactory.newInstance().newXPath();
      Object result = xPath.compile(expression).evaluate(d, XPathConstants.NODESET);

      return Optional.ofNullable((NodeList) result);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  /**
   * Constructs a XPath query to the supplied node.
   */
  public static String getXPath(Node n) {
    // abort early
    if (null == n) {
      return null;
    }

    // declarations
    Node parent;
    Stack<Node> hierarchy = new Stack<>();
    StringBuilder buffer = new StringBuilder();

    // push element on stack
    hierarchy.push(n);

    parent = n.getParentNode();
    while (null != parent && parent.getNodeType() != Node.DOCUMENT_NODE) {
      // push on stack
      hierarchy.push(parent);

      // get parent of parent
      parent = parent.getParentNode();
    }

    // construct xpath
    Object obj;
    while (!hierarchy.isEmpty() && null != (obj = hierarchy.pop())) {
      Node node = (Node) obj;
      boolean handled = false;

      // only consider elements
      if (node.getNodeType() == Node.ELEMENT_NODE) {
        Element e = (Element) node;

        // is this the root element?
        if (buffer.length() == 0) {
          // root element - simply append element name
          buffer.append(node.getLocalName());
        } else {
          // child element - append slash and element name
          buffer.append("/");
          buffer.append(node.getLocalName());

          if (node.hasAttributes()) {
            // see if the element has a name or id attribute
            if (e.hasAttribute("id")) {
              // id attribute found - use that
              buffer.append("[@id='").append(e.getAttribute("id")).append("']");
              handled = true;
            } else if (e.hasAttribute("name")) {
              // name attribute found - use that
              buffer.append("[@name='").append(e.getAttribute("name")).append("']");
              handled = true;
            } else if (e.hasAttribute("URI")) {
              // name attribute found - use that
              buffer.append("[@URI='").append(e.getAttribute("URI")).append("']");
              handled = true;
            }
          }

          if (!handled) {
            // no known attribute we could use - get sibling index
            int prev_siblings = 1;
            Node prev_sibling = node.getPreviousSibling();
            while (null != prev_sibling) {
              if (prev_sibling.getNodeType() == node.getNodeType()) {
                if (prev_sibling.getLocalName().equalsIgnoreCase(node.getLocalName())) {
                  prev_siblings++;
                }
              }
              prev_sibling = prev_sibling.getPreviousSibling();
            }
            buffer.append("[").append(prev_siblings).append("]");
          }
        }
      }
    }

    // return buffer
    return buffer.toString();
  }

}
