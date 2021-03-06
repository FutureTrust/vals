//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.09.23 at 10:24:46 PM CEST 
//


package org.rub.nds.futuretrust.cvs.sso.api;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for verificationProfileType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="verificationProfileType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="samlTokenVerificationChecks" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}samlTokenVerificationChecksType" minOccurs="0"/>
 *         &lt;element name="samlAuthnReqVerificationChecks" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}samlAuthnRequestVerificationChecksType" minOccurs="0"/>
 *         &lt;element name="samlTokenVerificationParameters" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}samlVerificationParametersType" minOccurs="0"/>
 *         &lt;element name="oidcVerificationChecks" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}oidcVerificationChecksType" minOccurs="0"/>
 *         &lt;element name="oidcVerificationParameters" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}oidcVerificationParametersType" minOccurs="0"/>
 *         &lt;element name="log" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}verificationLogType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ID" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "verificationProfileType", propOrder = {
    "samlTokenVerificationChecks",
    "samlAuthnReqVerificationChecks",
    "samlTokenVerificationParameters",
    "oidcVerificationChecks",
    "oidcVerificationParameters",
    "log"
})
public class VerificationProfileType {

    protected SamlTokenVerificationChecksType samlTokenVerificationChecks;
    protected SamlAuthnRequestVerificationChecksType samlAuthnReqVerificationChecks;
    protected SamlVerificationParametersType samlTokenVerificationParameters;
    protected OidcVerificationChecksType oidcVerificationChecks;
    protected OidcVerificationParametersType oidcVerificationParameters;
    protected VerificationLogType log;
    @XmlAttribute(name = "ID", required = true)
    protected String id;

    /**
     * Gets the value of the samlTokenVerificationChecks property.
     * 
     * @return
     *     possible object is
     *     {@link SamlTokenVerificationChecksType }
     *     
     */
    public SamlTokenVerificationChecksType getSamlTokenVerificationChecks() {
        return samlTokenVerificationChecks;
    }

    /**
     * Sets the value of the samlTokenVerificationChecks property.
     * 
     * @param value
     *     allowed object is
     *     {@link SamlTokenVerificationChecksType }
     *     
     */
    public void setSamlTokenVerificationChecks(SamlTokenVerificationChecksType value) {
        this.samlTokenVerificationChecks = value;
    }

    /**
     * Gets the value of the samlAuthnReqVerificationChecks property.
     * 
     * @return
     *     possible object is
     *     {@link SamlAuthnRequestVerificationChecksType }
     *     
     */
    public SamlAuthnRequestVerificationChecksType getSamlAuthnReqVerificationChecks() {
        return samlAuthnReqVerificationChecks;
    }

    /**
     * Sets the value of the samlAuthnReqVerificationChecks property.
     * 
     * @param value
     *     allowed object is
     *     {@link SamlAuthnRequestVerificationChecksType }
     *     
     */
    public void setSamlAuthnReqVerificationChecks(SamlAuthnRequestVerificationChecksType value) {
        this.samlAuthnReqVerificationChecks = value;
    }

    /**
     * Gets the value of the samlTokenVerificationParameters property.
     * 
     * @return
     *     possible object is
     *     {@link SamlVerificationParametersType }
     *     
     */
    public SamlVerificationParametersType getSamlTokenVerificationParameters() {
        return samlTokenVerificationParameters;
    }

    /**
     * Sets the value of the samlTokenVerificationParameters property.
     * 
     * @param value
     *     allowed object is
     *     {@link SamlVerificationParametersType }
     *     
     */
    public void setSamlTokenVerificationParameters(SamlVerificationParametersType value) {
        this.samlTokenVerificationParameters = value;
    }

    /**
     * Gets the value of the oidcVerificationChecks property.
     * 
     * @return
     *     possible object is
     *     {@link OidcVerificationChecksType }
     *     
     */
    public OidcVerificationChecksType getOidcVerificationChecks() {
        return oidcVerificationChecks;
    }

    /**
     * Sets the value of the oidcVerificationChecks property.
     * 
     * @param value
     *     allowed object is
     *     {@link OidcVerificationChecksType }
     *     
     */
    public void setOidcVerificationChecks(OidcVerificationChecksType value) {
        this.oidcVerificationChecks = value;
    }

    /**
     * Gets the value of the oidcVerificationParameters property.
     * 
     * @return
     *     possible object is
     *     {@link OidcVerificationParametersType }
     *     
     */
    public OidcVerificationParametersType getOidcVerificationParameters() {
        return oidcVerificationParameters;
    }

    /**
     * Sets the value of the oidcVerificationParameters property.
     * 
     * @param value
     *     allowed object is
     *     {@link OidcVerificationParametersType }
     *     
     */
    public void setOidcVerificationParameters(OidcVerificationParametersType value) {
        this.oidcVerificationParameters = value;
    }

    /**
     * Gets the value of the log property.
     * 
     * @return
     *     possible object is
     *     {@link VerificationLogType }
     *     
     */
    public VerificationLogType getLog() {
        return log;
    }

    /**
     * Sets the value of the log property.
     * 
     * @param value
     *     allowed object is
     *     {@link VerificationLogType }
     *     
     */
    public void setLog(VerificationLogType value) {
        this.log = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getID() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setID(String value) {
        this.id = value;
    }

}
