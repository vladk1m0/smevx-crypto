package ru.smevx.crypto.smev2.wss;

import org.apache.commons.lang3.StringUtils;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.UUIDGenerator;
import org.apache.ws.security.util.XMLUtils;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static ru.CryptoPro.JCPxml.Consts.URI_GOST_DIGEST;
import static ru.CryptoPro.JCPxml.Consts.URI_GOST_SIGN;

/**
 * Класс {@link WSSecurityUtils} реализующий методы формирования и проверки ЭП-ОВ в соответствии с п. 5.1 документа  "Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х".
 *
 * @author Vladislav Mostovoi
 * @see <a target="_blank" href="https://smev.gosuslugi.ru/portal/api/files/get/28834">Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х</a>
 * @since 1.0
 */
public class WSSecurityUtils {

    private static final String NS_XMLNS = "http://www.w3.org/2000/xmlns/";
    private static final String NS_ACTOR_SMEV = "http://smev.gosuslugi.ru/actors/smev";
    private static final String NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String NS_WSS_X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private static final String NS_WSS_BASE64_BINARY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    private static final String NS_XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

    static {
        org.apache.xml.security.Init.init();
        // Инициализация КритптоПРО JCP сервис-провайдера.
        if (!JCPXMLDSigInit.isInitialized()) {
            JCPXMLDSigInit.init();
        }
    }

    /**
     * Медод формирование ЭП-ОВ в формате WS-Security для элемента DOM дерева /Envelope/Body (в соответствии с МР СМЭВ 2.Х).
     *
     * @param privateKey приватный ключ, значение не может быть null.
     * @param cert       сертификат проверки ЭП, значение не может быть null.
     * @param soapText   строка содержащее валидное SOAP-сообщение, значение не может быть пустым.
     * @return в случае успешного выполнеия подписанное SOAP-сообщение, иначе исключение.
     * @throws GeneralSecurityException
     * @throws SOAPException
     * @throws ParserConfigurationException
     * @throws TransformerException
     * @throws WSSecurityException
     * @throws FileNotFoundException
     * @throws TransformationException
     * @throws MarshalException
     * @throws XMLSignatureException
     */
    public static String sign(final PrivateKey privateKey, final X509Certificate cert, final String soapText) throws GeneralSecurityException,
            SOAPException, TransformerException,
            WSSecurityException, TransformationException, MarshalException, XMLSignatureException {

        if (privateKey == null) {
            throw new IllegalArgumentException("Argument [privateKey] can't be null");
        }

        if (cert == null) {
            throw new IllegalArgumentException("Argument [cert] can't be null");
        }

        if (StringUtils.isBlank(soapText)) {
            throw new IllegalArgumentException("Argument [soapText] can't be blank");
        }

        final SOAPMessage soapMessage = parseSoapMessage(soapText);
        final SOAPMessage signSoapMsg = sign(privateKey, cert, soapMessage);
        return XMLUtils.PrettyDocumentToString(signSoapMsg.getSOAPPart());
    }

    /**
     * Медод формирование ЭП-ОВ в формате WS-Security для элемента DOM дерева /Envelope/Body (в соответствии с МР СМЭВ 2.Х).
     *
     * @param privateKey  приватный ключ, значение не может быть null.
     * @param cert        сертификат проверки ЭП, значение не может быть null.
     * @param soapMessage объект содержащее валидное SOAP-сообщение, значение не может быть пустым.
     * @return в случае успешного выполнеия подписанное SOAP-сообщение, иначе исключение.
     * @throws GeneralSecurityException
     * @throws SOAPException
     * @throws ParserConfigurationException
     * @throws TransformerException
     * @throws WSSecurityException
     * @throws FileNotFoundException
     * @throws TransformationException
     * @throws MarshalException
     * @throws XMLSignatureException
     */
    public static SOAPMessage sign(final PrivateKey privateKey, final X509Certificate cert, final SOAPMessage soapMessage) throws GeneralSecurityException,
            SOAPException, TransformerException,
            WSSecurityException, TransformationException, MarshalException, XMLSignatureException {

        if (privateKey == null) {
            throw new IllegalArgumentException("Argument [privateKey] can't be null");
        }

        if (cert == null) {
            throw new IllegalArgumentException("Argument [cert] can't be null");
        }

        if (soapMessage == null) {
            throw new IllegalArgumentException("Argument [soapMessage] can't be null");
        }

        // Обявляем Web Service Security namespaces в SOAP конверте.
        final SOAPEnvelope envelope = soapMessage.getSOAPPart().getEnvelope();
        envelope.addNamespaceDeclaration("wsse", NS_WSSE);
        envelope.addNamespaceDeclaration("wsu", NS_WSU);
        envelope.addNamespaceDeclaration("ds", NS_XMLDSIG);
        soapMessage.getSOAPBody().setAttributeNS(NS_WSU, "wsu:Id", "body");

        // Добавляем SOAP - заголовок WSSecurity в соответствии с документом метод. реккомендации 2.х .
        final WSSecHeader header = new WSSecHeader();
        header.setActor(NS_ACTOR_SMEV);
        header.setMustUnderstand(false);

        final Element sec = header.insertSecurityHeader(soapMessage.getSOAPPart());
        final Document doc = envelope.getOwnerDocument();

        final String certId = String.valueOf(String.format("CertId-%s", UUIDGenerator.getUUID()));

        final Element token = (Element) sec.appendChild(doc.createElementNS(NS_WSSE, "wsse:BinarySecurityToken"));
        token.setAttribute("EncodingType", NS_WSS_BASE64_BINARY);
        token.setAttribute("ValueType", NS_WSS_X509V3);
        token.setAttribute("wsu:Id", certId);
        header.getSecurityHeader().appendChild(token);

        // Каноникализация SOAP - сообщения перед подписанием.
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        // Получаем экземпляр фабрики, порождающей КритптоПРО XMLSecurity провайдеры с поддержкой ГОСТ криптоалгоритмов.
        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        final List<Transform> transformList = new ArrayList<>();
        final Transform transformC14N = fac.newTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (XMLStructure) null);
        transformList.add(transformC14N);

        // Создаем ссылку на элемент Body SOAP - сообщения.
        final Reference ref = fac.newReference("#body", fac.newDigestMethod(URI_GOST_DIGEST, null), transformList, null, null);

        // Создаем элемент содержащий информацию о ЭП SOAP - сообщения.
        final SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(URI_GOST_SIGN, null),
                Collections.singletonList(ref));

        // Получение public key из сертификата.
        final KeyInfoFactory kif = fac.getKeyInfoFactory();
        final X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
        final KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));

        // Подписание SOAP - сообщения.
        final XMLSignature sig = fac.newXMLSignature(si, ki);
        final DOMSignContext signContext = new DOMSignContext(privateKey, token);
        sig.sign(signContext);

        // Добавление ссылки на сертификат в SOAP - сообщение.
        final Element sigE = (Element) XPathAPI.selectSingleNode(signContext.getParent(), "//ds:Signature");
        sigE.setAttribute("Id", String.format("Signature-%s", UUIDGenerator.getUUID().substring(0, 7)));

        final Node keyE = XPathAPI.selectSingleNode(sigE, "//ds:KeyInfo", sigE);
        token.appendChild(doc.createTextNode(XPathAPI.selectSingleNode(keyE, "//ds:X509Certificate", keyE).getFirstChild().getNodeValue()));
        keyE.removeChild(XPathAPI.selectSingleNode(keyE, "//ds:X509Data", keyE));

        final NodeList chl = keyE.getChildNodes();
        for (int i = 0; i < chl.getLength(); i++) {
            keyE.removeChild(chl.item(i));
        }

        final String strId = String.valueOf(String.format("STRId-%s", UUIDGenerator.getUUID()));
        final Element str = (Element) keyE.appendChild(doc.createElementNS(NS_WSSE, "wsse:SecurityTokenReference"));
        str.setAttribute("wsu:Id", strId);

        final Element strRef = (Element) str.appendChild(doc.createElementNS(NS_WSSE, "wsse:Reference"));
        strRef.setAttribute("ValueType", NS_WSS_X509V3);
        strRef.setAttribute("URI", "#" + certId);
        header.getSecurityHeader().appendChild(sigE);

        return soapMessage;
    }

    /**
     * Медод проверки ЭП-ОВ в формате WS-Security (в соответствии с МР СМЭВ 2.Х).
     *
     * @param wssSoap строка содержащее валидное подписанное SOAP-сообщение, значение не может быть пустым.
     * @return true, если подпись корректна, иначе false.
     * @throws XMLSignatureException
     * @throws CertificateException
     * @throws WSSecurityException
     * @throws TransformerException
     * @throws SOAPException
     * @throws MarshalException
     */
    public static boolean validate(String wssSoap) throws XMLSignatureException, CertificateException, WSSecurityException, TransformerException, SOAPException, MarshalException {

        if (StringUtils.isBlank(wssSoap)) {
            throw new IllegalArgumentException("Argument [wssSoap] must be not empty");
        }

        // Загрузка SOAP - сообщения.
        final SOAPMessage message = parseSoapMessage(wssSoap);
        final Document doc = message.getSOAPPart().getEnvelope().getOwnerDocument();

        // Поиск узла с информацией о подписи SOAP - сообщения.
        final Element wsseContext = doc.createElementNS(null, "namespaceContext");
        wsseContext.setAttributeNS(NS_XMLNS, "xmlns:wsse", NS_WSSE);
        final NodeList wssElements = XPathAPI.selectNodeList(doc.getDocumentElement(), "//wsse:Security");

        // Поиск узла с информацией о сертификате BinarySecurityToken.
        Element bst = null;
        if (wssElements != null && wssElements.getLength() > 0) {
            for (int i = 0; i < wssElements.getLength(); i++) {
                final Element el = (Element) wssElements.item(i);
                final String actorAttr = el.getAttributeNS(NS_SOAP, "actor");
                if (actorAttr != null && actorAttr.equals(NS_ACTOR_SMEV)) {
                    bst = (Element) XPathAPI.selectSingleNode(el, "//wsse:BinarySecurityToken[1]", wsseContext);
                    break;
                }
            }
        }
        if (bst == null) {
            return false;
        }

        final X509Security x509 = new X509Security(bst);
        final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x509.getToken()));
        if (cert == null) {
            throw new IllegalStateException("Сертификат не найден.");
        }

        // Поиск узла со значением ЭП SOAP - сообщения.
        final NodeList nl = doc.getElementsByTagNameNS(NS_XMLDSIG, "Signature");
        if (nl.getLength() == 0) {
            throw new IllegalStateException("Не найден элемент Signature.");
        }

        // Инициализация сертификатом контекста валидации SOAP - сообщения.
        final DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(cert.getPublicKey()), nl.item(0));

        // Получаем экземпляр фабрики, порождающей КритптоПРО XMLSecurity провайдеры с поддержкой ГОСТ криптоалгоритмов.
        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        final XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        return signature.validate(valContext);
    }

    /**
     * Метод парсинга SOAP-сообщения из текстового представления в строке в объект SOAPMessage.
     *
     * @param text текстовое представление SOAP-сообщения.
     * @return обект SOAPMessage
     * @throws SOAPException
     */
    public static SOAPMessage parseSoapMessage(final String text) throws SOAPException {
        if (StringUtils.isBlank(text)) {
            throw new IllegalArgumentException("Argument [soap] can't be blank");
        }

        final MessageFactory mf = MessageFactory.newInstance();
        final SOAPMessage message = mf.createMessage();
        final SOAPPart soapPart = message.getSOAPPart();
        final ByteArrayInputStream is = new ByteArrayInputStream(StringUtils.trim(text).getBytes());
        soapPart.setContent(new StreamSource(is));
        return message;
    }
}
