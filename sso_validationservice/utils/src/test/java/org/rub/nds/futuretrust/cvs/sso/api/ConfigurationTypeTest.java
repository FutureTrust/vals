package org.rub.nds.futuretrust.cvs.sso.api;

import java.io.File;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Vladislav Mladenov
 */
public class ConfigurationTypeTest {
    
    public ConfigurationTypeTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of getID method, of class ConfigurationType.
     */
    @Test
    public void testConfig() throws JAXBException {
        JAXBContext jaxbContext = JAXBContext.newInstance ("org.rub.nds.futuretrust.cvs.sso.api");
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
         JAXBElement<DatabaseType> samlStorage = (JAXBElement<DatabaseType>) unmarshaller.unmarshal( 
                 new File("src/test/resources/samlIdPExample.xml"));
         DatabaseType storage = samlStorage.getValue();
         
         VerificationProfileType verifierProfile = storage.getRegisteredEntity().get(0).verificationProfile.get(0);
         assertEquals(storage.getRegisteredEntity().get(0).authentication.get(0).clientId, "11111");
         assertEquals(storage.getRegisteredEntity().get(0).authentication.get(0).clientSecret, "secret");
         assertEquals(storage.getRegisteredEntity().get(0).authentication.get(0).clientCert, "xxxx");
         assertEquals(storage.getRegisteredEntity().get(0).authentication.get(1).clientId, "sp_admin");
         assertEquals(storage.getRegisteredEntity().get(0).authentication.get(1).clientSecret, "secret2");
         
         assertEquals(verifierProfile.getID(), "1");
         assertNull(verifierProfile.getSamlTokenVerificationChecks().verifiyHolderOfKey);
         assertNull(verifierProfile.getSamlTokenVerificationChecks().verifySAMLResponseIssueInstant);
         assertNull(verifierProfile.getSamlTokenVerificationChecks().verifySAMLResponseInResponseTo);
         assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifySchema);
         assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifyXSW);
         assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifySAMLResponseID);
         assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifiySAMLAssertionID);
         assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifiySAMLAssertionSignatureTrusted);
         assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifySAMLAssertionSbjConfirmationTimestamps);
         assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifiySAMLAssertionSbjConfirmationDestination);
         
         
          verifierProfile = storage.getRegisteredEntity().get(0).verificationProfile.get(1);
          assertEquals(verifierProfile.getID(), "2");
          assertTrue(verifierProfile.getSamlTokenVerificationChecks().verifySAMLResponseID);
          assertEquals(verifierProfile.getSamlTokenVerificationParameters().x509Certificate, "xxxx");
          assertEquals(verifierProfile.getSamlTokenVerificationParameters().destination, "http://sp.com/saml");
          assertEquals(verifierProfile.getSamlTokenVerificationParameters().samlMetadataUrl, "/src/main/resources/samlSPMetadata.xml");
    }

    
}
