/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.rub.nds.futuretrust.cvs.sso.api;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.xml.ConfigurationException;
import org.rub.nds.saml.samllib.exceptions.SAMLVerifyException;
import org.rub.nds.saml.samllib.exceptions.WrongInputException;
import org.rub.nds.saml.samllib.utils.FileUtils;
import org.rub.nds.saml.samllib.utils.HTTPUtils;
import org.rub.nds.saml.samllib.utils.SAMLUtils;
import org.rub.nds.saml.samllib.verifier.SAMLVerifierImpl;
import org.rub.nds.saml.samllib.verifier.SAMLVerifierInterface;

/**
 *
 * @author vladi
 */
public class VerificationTest {

    public VerificationTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws ConfigurationException {
        DefaultBootstrap.bootstrap();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void exampleTest() throws IOException, WrongInputException, SAMLVerifyException {
        SAMLVerifierInterface samlVerifier;
        VerificationProfileType profile;

        samlVerifier = new SAMLVerifierImpl();
        profile = new VerificationProfileType();

        SamlTokenVerificationChecksType check = new SamlTokenVerificationChecksType();
        check.setVerifiySAMLAssertionSignature(Boolean.TRUE);
        profile.setSamlTokenVerificationChecks(check);

        for (String s : FileUtils.readFilesFromDir("src/test/resources/tokens", "txt")) {
            String decodedString = new String(HTTPUtils.decodeSamlObject(s));
            SAMLObject samlToken = SAMLUtils.buildObjectfromString(decodedString);
            samlVerifier.verify(samlToken, profile);
        }
    }
}
