//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.09.23 at 09:36:42 PM CEST 
//


package oasis.names.tc.saml._1_0.assertion;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SubjectStatementAbstractType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SubjectStatementAbstractType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:oasis:names:tc:SAML:1.0:assertion}StatementAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:1.0:assertion}Subject"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SubjectStatementAbstractType", propOrder = {
    "subject"
})
@XmlSeeAlso({
    AuthorizationDecisionStatementType.class,
    AuthenticationStatementType.class,
    AttributeStatementType.class
})
public abstract class SubjectStatementAbstractType
    extends StatementAbstractType
{

    @XmlElement(name = "Subject", required = true)
    protected SubjectType subject;

    /**
     * Gets the value of the subject property.
     * 
     * @return
     *     possible object is
     *     {@link SubjectType }
     *     
     */
    public SubjectType getSubject() {
        return subject;
    }

    /**
     * Sets the value of the subject property.
     * 
     * @param value
     *     allowed object is
     *     {@link SubjectType }
     *     
     */
    public void setSubject(SubjectType value) {
        this.subject = value;
    }

}
