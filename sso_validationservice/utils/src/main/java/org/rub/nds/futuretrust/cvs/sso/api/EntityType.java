//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.09.23 at 10:24:46 PM CEST 
//


package org.rub.nds.futuretrust.cvs.sso.api;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for EntityType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="EntityType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="authentication" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}authentication_Type" maxOccurs="unbounded"/>
 *         &lt;element name="verificationProfile" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}verificationProfileType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EntityType", propOrder = {
    "authentication",
    "verificationProfile"
})
public class EntityType {

    @XmlElement(required = true)
    protected List<AuthenticationType> authentication;
    @XmlElement(required = true)
    protected List<VerificationProfileType> verificationProfile;

    /**
     * Gets the value of the authentication property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the authentication property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAuthentication().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link AuthenticationType }
     * 
     * 
     */
    public List<AuthenticationType> getAuthentication() {
        if (authentication == null) {
            authentication = new ArrayList<AuthenticationType>();
        }
        return this.authentication;
    }

    /**
     * Gets the value of the verificationProfile property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the verificationProfile property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getVerificationProfile().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link VerificationProfileType }
     * 
     * 
     */
    public List<VerificationProfileType> getVerificationProfile() {
        if (verificationProfile == null) {
            verificationProfile = new ArrayList<VerificationProfileType>();
        }
        return this.verificationProfile;
    }

}