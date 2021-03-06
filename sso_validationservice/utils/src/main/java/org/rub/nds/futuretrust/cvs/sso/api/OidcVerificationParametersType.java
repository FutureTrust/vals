//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.09.23 at 10:24:46 PM CEST 
//


package org.rub.nds.futuretrust.cvs.sso.api;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for oidcVerificationParametersType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="oidcVerificationParametersType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="x509certificate" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="audience" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="oidc_metadata" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="oidc_metadata_url" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="time_limitation" type="{http://www.w3.org/2001/XMLSchema}time" minOccurs="0"/>
 *         &lt;element name="pkceParameters" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}pkceParametersType" minOccurs="0"/>
 *         &lt;element name="client_secret" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="cnf" type="{http://www.api.sso.cvs.futuretrust.nds.rub.org}proofOfPossessionType" minOccurs="0"/>
 *         &lt;element name="code" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="accessToken" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="subClaims" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "oidcVerificationParametersType", propOrder = {
    "x509Certificate",
    "audience",
    "oidcMetadata",
    "oidcMetadataUrl",
    "timeLimitation",
    "pkceParameters",
    "clientSecret",
    "cnf",
    "code",
    "accessToken",
    "subClaims"
})
public class OidcVerificationParametersType {

    @XmlElement(name = "x509certificate")
    protected String x509Certificate;
    protected String audience;
    @XmlElement(name = "oidc_metadata")
    protected String oidcMetadata;
    @XmlElement(name = "oidc_metadata_url")
    protected String oidcMetadataUrl;
    @XmlElement(name = "time_limitation")
    @XmlSchemaType(name = "time")
    protected XMLGregorianCalendar timeLimitation;
    protected PkceParametersType pkceParameters;
    @XmlElement(name = "client_secret")
    protected String clientSecret;
    protected ProofOfPossessionType cnf;
    @XmlElement(required = true)
    protected String code;
    @XmlElement(required = true)
    protected String accessToken;
    @XmlElement(required = true)
    protected String subClaims;

    /**
     * Gets the value of the x509Certificate property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getX509Certificate() {
        return x509Certificate;
    }

    /**
     * Sets the value of the x509Certificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setX509Certificate(String value) {
        this.x509Certificate = value;
    }

    /**
     * Gets the value of the audience property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAudience() {
        return audience;
    }

    /**
     * Sets the value of the audience property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAudience(String value) {
        this.audience = value;
    }

    /**
     * Gets the value of the oidcMetadata property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOidcMetadata() {
        return oidcMetadata;
    }

    /**
     * Sets the value of the oidcMetadata property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOidcMetadata(String value) {
        this.oidcMetadata = value;
    }

    /**
     * Gets the value of the oidcMetadataUrl property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOidcMetadataUrl() {
        return oidcMetadataUrl;
    }

    /**
     * Sets the value of the oidcMetadataUrl property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOidcMetadataUrl(String value) {
        this.oidcMetadataUrl = value;
    }

    /**
     * Gets the value of the timeLimitation property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getTimeLimitation() {
        return timeLimitation;
    }

    /**
     * Sets the value of the timeLimitation property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setTimeLimitation(XMLGregorianCalendar value) {
        this.timeLimitation = value;
    }

    /**
     * Gets the value of the pkceParameters property.
     * 
     * @return
     *     possible object is
     *     {@link PkceParametersType }
     *     
     */
    public PkceParametersType getPkceParameters() {
        return pkceParameters;
    }

    /**
     * Sets the value of the pkceParameters property.
     * 
     * @param value
     *     allowed object is
     *     {@link PkceParametersType }
     *     
     */
    public void setPkceParameters(PkceParametersType value) {
        this.pkceParameters = value;
    }

    /**
     * Gets the value of the clientSecret property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Sets the value of the clientSecret property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setClientSecret(String value) {
        this.clientSecret = value;
    }

    /**
     * Gets the value of the cnf property.
     * 
     * @return
     *     possible object is
     *     {@link ProofOfPossessionType }
     *     
     */
    public ProofOfPossessionType getCnf() {
        return cnf;
    }

    /**
     * Sets the value of the cnf property.
     * 
     * @param value
     *     allowed object is
     *     {@link ProofOfPossessionType }
     *     
     */
    public void setCnf(ProofOfPossessionType value) {
        this.cnf = value;
    }

    /**
     * Gets the value of the code property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCode() {
        return code;
    }

    /**
     * Sets the value of the code property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCode(String value) {
        this.code = value;
    }

    /**
     * Gets the value of the accessToken property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Sets the value of the accessToken property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAccessToken(String value) {
        this.accessToken = value;
    }

    /**
     * Gets the value of the subClaims property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSubClaims() {
        return subClaims;
    }

    /**
     * Sets the value of the subClaims property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSubClaims(String value) {
        this.subClaims = value;
    }

}
