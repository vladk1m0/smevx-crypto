package ru.smevx.crypto.smev2.xmldsig;

import org.apache.commons.lang3.StringUtils;
import org.apache.ws.security.util.UUIDGenerator;
import org.apache.ws.security.util.XMLUtils;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;
import static org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;
import static ru.CryptoPro.JCPxml.Consts.URI_GOST_DIGEST;
import static ru.CryptoPro.JCPxml.Consts.URI_GOST_SIGN;
import static ru.smevx.crypto.smev2.wss.WSSecurityUtils.parseSoapMessage;

/**
 * Класс {@link XmlDSignUtils} реализующий методы формирования и проверки ЭП-СП сообщений без вложений в соответствии с п. 4.4 документа  "Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х".
 *
 * @author Vladislav Mostovoi
 * @see <a target="_blank" href="https://smev.gosuslugi.ru/portal/api/files/get/28834">Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х</a>
 * @since 1.0
 */
public class XmlDSignUtils {

    static {
        org.apache.xml.security.Init.init();
        // Инициализация КритптоПРО JCP сервис-провайдера.
        if (!JCPXMLDSigInit.isInitialized()) {
            JCPXMLDSigInit.init();
        }
    }

    /**
     * Медод формирование ЭП-СП в формате XMLDSign для элемента DOM дерева /Envelope/Body/~/MessageData/AppData (в соответствии с МР СМЭВ 2.Х).
     *
     * @param privateKey приватный ключ, значение не может быть null.
     * @param cert       сертификат проверки ЭП, значение не может быть null.
     * @param soap       строка содержащее валидное SOAP-сообщение, значение не может быть пустым.
     * @return в случае успешного выполнеия подписанное SOAP-сообщение, иначе исключение.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws SOAPException
     * @throws TransformerException
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     * @throws MarshalException
     * @throws XMLSignatureException
     */
    public static String sign(final PrivateKey privateKey, final X509Certificate cert, final String soap) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SOAPException, TransformerException, MarshalException, XMLSignatureException {

        if (privateKey == null) {
            throw new IllegalArgumentException("Argument [privateKey] can't be null");
        }

        if (cert == null) {
            throw new IllegalArgumentException("Argument [cert] can't be null");
        }

        if (StringUtils.isBlank(soap)) {
            throw new IllegalArgumentException("Argument [xml] can't be blank");
        }

        final SOAPMessage mf = parseSoapMessage(soap);
        final Document doc = mf.getSOAPPart().getEnvelope().getOwnerDocument();

        final Element appDataNode = (Element) XPathAPI.selectSingleNode(doc, "//*[local-name()='MessageData']/*[local-name()='AppData']");
        appDataNode.setAttribute("Id", "AppData");

        // Fix, see description https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=5640.
        Attr attributeNode = appDataNode.getAttributeNode("Id");
        if (attributeNode != null) {
            appDataNode.setIdAttributeNode(attributeNode, true);
        }

        // Получаем экземпляр фабрики, порождающей КритптоПРО XMLSecurity провайдеры с поддержкой ГОСТ криптоалгоритмов.
        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        final DigestMethod digestMethodObj = fac.newDigestMethod(URI_GOST_DIGEST, null);

        final List<Transform> transformList = new ArrayList<>();
        transformList.add(fac.newTransform(ENVELOPED, (TransformParameterSpec) null));
        transformList.add(fac.newTransform(TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null));

        final Reference ref = fac.newReference("#AppData", digestMethodObj, transformList, null, null);

        final CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(EXCLUSIVE, (C14NMethodParameterSpec) null);

        final List<Reference> referenceList = Collections.singletonList(ref);
        final SignatureMethod signatureMethodObj = fac.newSignatureMethod(URI_GOST_SIGN, null);
        final SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethodObj, referenceList);

        final KeyInfoFactory kif = fac.getKeyInfoFactory();
        final X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
        final KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));

        final XMLSignature signature = fac.newXMLSignature(si, ki);
        final DOMSignContext signContext = new DOMSignContext(privateKey, appDataNode, appDataNode.getFirstChild());

        signature.sign(signContext);
        // Добавление ссылки на сертификат в SOAP - сообщение.
        final Element sigE = (Element) XPathAPI.selectSingleNode(signContext.getParent(), "//*[local-name()='Signature']");
        sigE.setAttribute("Id", String.format("Signature-%s", UUIDGenerator.getUUID().substring(0, 7)));

        return XMLUtils.PrettyDocumentToString(doc);
    }

    /**
     * Медод проверки ЭП-СП в формате XMLDSign для элемента DOM дерева /Envelope/Body/~/MessageData/AppData (в соответствии с МР СМЭВ 2.Х).
     *
     * @param soap строка содержащее валидное подписанное SOAP-сообщение, значение не может быть пустым.
     * @return true, если подпись корректна, иначе false.
     * @throws XMLSignatureException
     * @throws CertificateException
     * @throws TransformerException
     * @throws SOAPException
     * @throws MarshalException
     */
    public static boolean validate(String soap) throws XMLSignatureException, CertificateException, TransformerException, SOAPException, MarshalException {

        if (StringUtils.isBlank(soap)) {
            throw new IllegalArgumentException("Argument [soap] must be not empty");
        }

        final SOAPMessage mf = parseSoapMessage(soap);
        final Document doc = mf.getSOAPPart().getEnvelope().getOwnerDocument();

        final Element signatureElement = (Element) XPathAPI.selectSingleNode(doc,
                "//*[local-name()='MessageData']/*[local-name()='AppData']/*[local-name()='Signature']");
        if (signatureElement == null) {
            return false;
        }

        final Element certElement = (Element) XPathAPI.selectSingleNode(signatureElement, "//*[local-name()='X509Certificate']");
        if (certElement == null) {
            return false;
        }

        final String certDER = "-----BEGIN CERTIFICATE-----\n" +
                certElement.getTextContent() +
                "\n-----END CERTIFICATE-----";
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bais = new ByteArrayInputStream(certDER.getBytes());
        final X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);

        final DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(cert.getPublicKey()), signatureElement);

        // Получаем экземпляр фабрики, порождающей КритптоПРО XMLSecurity провайдеры с поддержкой ГОСТ криптоалгоритмов.
        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        final XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        return signature.validate(valContext);
    }
}
