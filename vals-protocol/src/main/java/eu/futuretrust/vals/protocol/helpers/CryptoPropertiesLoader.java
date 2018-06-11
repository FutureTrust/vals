package eu.futuretrust.vals.protocol.helpers;

import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoPropertiesLoader {

  private static final Logger LOGGER = LoggerFactory.getLogger(CryptoPropertiesLoader.class);

  private static String CRYPTO_PROPERTIES_FILE = "protocol-crypto.properties";
  private static String KEY_STORE_TYPE = "PKCS12";
  private static String MESSAGE_DIGEST_PROPERTY = "message.digest";
  private static String TSL_VALIDATION_KEYSTORE_NAME_PROPERTY = "tsl.validation.keystore.name";
  private static String TSL_VALIDATION_KEYSTORE_PASSWORD_PROPERTY = "tsl.validation.keystore.password";
  private static String TRUSTED_CA_CRT_PATH_PROPERTY = "trusted.ca.crt.path";
  private static String VALIDATION_REPORT_SIGNING_KEYSTORE_NAME_PROPERTY = "validation.report.signing.keystore.name";
  private static String VALIDATION_REPORT_SIGNING_KEYSTORE_PASSWORD_PROPERTY = "validation.report.signing.keystore.password";
  private static String TSL_LOADING_CACHE_PATH_PROPERTY = "tsl.loading.cache.path";

  public String getMessageDigest() throws IOException {
    return getProperty(MESSAGE_DIGEST_PROPERTY);
  }

  public String getTslValidationKeystoreName() throws IOException {
    return getProperty(TSL_VALIDATION_KEYSTORE_NAME_PROPERTY);
  }

  public String getTslValidationKeystorePassword() throws IOException {
    return getProperty(TSL_VALIDATION_KEYSTORE_PASSWORD_PROPERTY);
  }

  public String getTrustedCaCrtPath() throws IOException {
    return getProperty(TRUSTED_CA_CRT_PATH_PROPERTY);
  }

  public String getValidationReportSigningKeystoreName() throws IOException {
    return getProperty(VALIDATION_REPORT_SIGNING_KEYSTORE_NAME_PROPERTY);
  }

  public String getValidationReportSigningKeystorePassword() throws IOException {
    return getProperty(VALIDATION_REPORT_SIGNING_KEYSTORE_PASSWORD_PROPERTY);
  }

  public String getTslLoadingCachePath() throws IOException {
    return getProperty(TSL_LOADING_CACHE_PATH_PROPERTY);
  }

  public KeyStoreCertificateSource getTslValidationKeystore() throws IOException {
    String keyStoreName = getProperty(TSL_VALIDATION_KEYSTORE_NAME_PROPERTY);
    String keyStorePassword = getProperty(TSL_VALIDATION_KEYSTORE_PASSWORD_PROPERTY);

    KeyStoreCertificateSource keyStoreCertificateSource;
    InputStream keystore = ResourcesUtils.loadInputStream(keyStoreName);

    if (keystore == null) {
      throw new IOException("Unable to load keystore file named " + keyStoreName);
    }
    keyStoreCertificateSource = new KeyStoreCertificateSource(keystore, KEY_STORE_TYPE,
        keyStorePassword);
    return keyStoreCertificateSource;
  }

  private String getProperty(String propertyName) throws IOException {
    InputStream cryptoPropertiesIS = ResourcesUtils.loadInputStream(CRYPTO_PROPERTIES_FILE);
    Properties p = new Properties();
    p.load(cryptoPropertiesIS);
    String propertyValue = p.getProperty(propertyName);
    cryptoPropertiesIS.close();
    return propertyValue;
  }

  public Pkcs12SignatureToken getValidationReportSigningKeyStore() throws IOException {
    String keyStoreName = getProperty(VALIDATION_REPORT_SIGNING_KEYSTORE_NAME_PROPERTY);
    String keyStorePassword = getProperty(VALIDATION_REPORT_SIGNING_KEYSTORE_PASSWORD_PROPERTY);

    InputStream keystore = ResourcesUtils.loadInputStream(keyStoreName);

    if (keystore == null) {
      throw new IOException("Unable to load keystore file named " + keyStoreName);
    }

    PasswordProtection passwordProtection = new PasswordProtection(keyStorePassword.toCharArray());
    return new Pkcs12SignatureToken(keystore, passwordProtection);
  }

  public KeyStore getValidationReportKeystore()
      throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    String keyStoreName = getProperty(VALIDATION_REPORT_SIGNING_KEYSTORE_NAME_PROPERTY);
    String keyStorePassword = getProperty(VALIDATION_REPORT_SIGNING_KEYSTORE_PASSWORD_PROPERTY);

    InputStream keystore = ResourcesUtils.loadInputStream(keyStoreName);

    if (keystore == null) {
      throw new IOException("Unable to load keystore file named " + keyStoreName);
    }
    KeyStore store = KeyStore.getInstance(KEY_STORE_TYPE);
    store.load(keystore, keyStorePassword.toCharArray());
    return store;
  }
}
