package ru.voskhod.crypto.impl.csp_tj;

import ru.voskhod.crypto.KeyStoreWrapper;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class TrustedKeyStoreWrapperCSP implements KeyStoreWrapper {

    public static final String CURRENT_USER_KS_TYPE = "CurrentUser";
    public static final String LOCAL_COMPUTER_KS_TYPE = "LocalComputer";
    public static final String CURRENT_USER_CONTAINERS_KS_TYPE = "CurrentUser/Containers";

    private final KeyStore ks;

    /**
     * Загружает хранилище ключей указанного типа.
     */
    public TrustedKeyStoreWrapperCSP() throws Exception {
        ks = KeyStore.getInstance("CryptoProCSPKeyStore");
        InputStream stream = new ByteArrayInputStream(CURRENT_USER_CONTAINERS_KS_TYPE.getBytes("UTF-8"));
        ks.load(stream, null);
    }

    public PrivateKey getPrivateKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        alias = resolveAlias(alias);
        return (PrivateKey) ks.getKey(alias, password);
    }

    public X509Certificate getX509Certificate(String alias) throws CertificateException, KeyStoreException {
        alias = resolveAlias(alias);
        X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
        if (certificate == null)
            return null;
        return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }

    public KeyStore getKeyStore() {
        return ks;
    }

    //TODO Loskutov Нужен кэш, нужен поиск по алиасам для CSP под Linux.
    private String resolveAlias(String alias) {
        // TODO Loskutov, На линухе не пашет, ибо алимасы начинаются с HDIMAGE\\.
        return alias;
        /*if (!alias.contains("REGISTRY\\\\")) {
            return "REGISTRY\\\\" + alias;
        }
        return alias;*/
    }
}
