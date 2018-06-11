package eu.futuretrust.vals.protocol.enums;
/**
 *The element SignatureValidationProcessID shall contain an identifier that shall have one of the following
 values
 * urn.etsi.019102.validationprocess.Basic when the SVA performed the Validation Process for
 Basic Signatures as specified in ETSI EN 319 102-1 clause 5.3.
 * urn.etsi.019102.validationprocess.LTV when the SVA performed the Validation Process for
 Signatures with Time and Signatures with LongTerm- Validation Material as specified in ETSI EN 319 102-1
 clause 5.5.
 * urn.etsi.019102.validationprocess.LTA when the SVA performed the Validation process for
 Signatures providing Long Term Availability and Integrity of Validation Material as specified in ETSI EN 319
 102-1 clause 5.6.
 */
public enum SignatureValidationProcessID {

    BASIC("urn.etsi.019102.validationprocess.Basic"),
    LTV("urn.etsi.019102.validationprocess.LTV"),
    LTA("urn.etsi.019102.validationprocess.LTA");

    private String uri = null;

    private SignatureValidationProcessID(String uri) {
        this.uri = uri;
    }

    public String getURI() {
        return this.uri;
    }

}
