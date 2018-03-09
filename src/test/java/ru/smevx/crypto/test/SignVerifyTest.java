package ru.smevx.crypto.test;

import org.apache.commons.lang3.StringUtils;
import org.apache.xpath.XPathAPI;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import ru.smevx.crypto.smev2.cms.PKCS7Utils;
import ru.smevx.crypto.smev2.wss.WSSecurityUtils;
import ru.smevx.crypto.smev2.xmldsig.XmlDSignUtils;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SignVerifyTest {

    private PrivateKey privateKey;
    private X509Certificate cert;

    private static Document parseXML(String xml) throws Exception {
        if (StringUtils.isBlank(xml)) {
            throw new IllegalArgumentException("Argument [xml] can't be blank");
        }

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);

        final DocumentBuilder builder = factory.newDocumentBuilder();

        return builder.parse(new ByteArrayInputStream(xml.getBytes()));
    }

    private static String loadResource(String path) throws IOException {
        if (StringUtils.isBlank(path)) {
            throw new IllegalArgumentException("Argument [soap] can't be blank");
        }

        final URL url = Thread.currentThread().getContextClassLoader().getResource(path);
        final byte[] encoded = Files.readAllBytes(Paths.get(url.getPath()));
        return new String(encoded, "UTF-8");
    }

    @Before
    public void init() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException {
        final KeyStore keyStore = KeyStore.getInstance("HDImageStore");
        keyStore.load(null, null);
        privateKey = (PrivateKey) keyStore.getKey("Alias", "Password".toCharArray());
        cert = (X509Certificate) keyStore.getCertificate("Alias");
        Assert.assertNotNull("Private key can't be null", privateKey);
        Assert.assertNotNull("Cert can't be null", cert);
    }

    @Test
    public void smev2SignWss() throws Exception {
        final String soap = loadResource("smev2-test-msg.xml");
        final String wss = WSSecurityUtils.sign(privateKey, cert, soap);
        Assert.assertTrue(WSSecurityUtils.validate(wss));
    }

    @Test
    public void smev2SignXmlDSig() throws Exception {
        final String soap = loadResource("smev2-test-msg.xml");
        final String sign = XmlDSignUtils.sign(privateKey, cert, soap);
        Assert.assertTrue(XmlDSignUtils.validate(sign));
    }

    @Test
    public void smev2SignPKCS7() throws Exception {
        final byte[] soap = loadResource("smev2-test-msg.xml").getBytes();
        final byte[] sign = PKCS7Utils.sign(privateKey, cert, soap);
        Assert.assertTrue(PKCS7Utils.validate(sign, soap));
    }

    @Test
    public void smev3SignXmlDSig() throws Exception {
        String xml = loadResource("smev3-test-msg.xml");
        Document doc = parseXML(xml);
        Element data = (Element) XPathAPI.selectSingleNode(doc, "//*[local-name()='SenderProvidedRequestData']");
        Element sign = ru.smevx.crypto.smev3.xmldsig.XmlDSignUtils.sign(privateKey, cert, data);
        Assert.assertTrue(ru.smevx.crypto.smev3.xmldsig.XmlDSignUtils.validate(data, sign));
    }

    @Test
    public void smev3SignPKCS7() throws Exception {
        final byte[] msg = loadResource("smev3-test-msg.xml").getBytes();
        final byte[] sign = ru.smevx.crypto.smev3.cms.PKCS7Utils.sign(privateKey, cert, msg);
        Assert.assertTrue(ru.smevx.crypto.smev3.cms.PKCS7Utils.validate(sign, msg));
    }
}