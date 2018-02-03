package ru.voskhod.crypto.impl;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import ru.voskhod.crypto.exceptions.SignatureProcessingException;
import ru.voskhod.crypto.exceptions.SignatureValidationException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class DigitalSignatureProcessorImpl extends AbstractDigitalSignatureProcessor {

    public static final String DIGEST_METHOD = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    public static final String XMLDSIG_SIGN_METHOD = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";

    protected static final String XMLDSIG_DETACHED_TRANSFORM_METHOD = Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;
    protected static final String XMLDSIG_ENVELOPED_TRANSFORM_METHOD = Transforms.TRANSFORM_ENVELOPED_SIGNATURE;
    protected static final String WSSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    protected static final String EDS_ERROR_SIGNATURE_INVALID = "Ошибка проверки ЭП: Нарушена целостность ЭП";

    // ================================ Подпись XML

    protected Element signXMLDSig(Document argDocument, Element element2Sign, PrivateKey argPrivateKey, X509Certificate argCertificate, String argSignatureId, boolean enveloped) throws SignatureProcessingException {
        try {
            Element _element2Sign = element2Sign != null ? element2Sign : argDocument.getDocumentElement();
            String referenceURI = _element2Sign.getAttribute("Id");
            if (referenceURI == null || "".equals(referenceURI.trim())) {
                referenceURI = _element2Sign.getAttributeNS(WSSU_NS, "Id");
            }
            if (referenceURI == null || "".equals(referenceURI.trim())) {
                referenceURI = "";
            }

            //Fix, see description https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=5640.
            Attr attributeNode = _element2Sign.getAttributeNode("Id");
            if (attributeNode != null && !"".equals(attributeNode.getValue().trim())) {
                _element2Sign.setIdAttributeNode(attributeNode, true);
            }

            /* Добавление узла подписи <ds:Signature> в загруженный XML-документ */

            // инициализация объекта формирования ЭЦП в соответствии с алгоритмом ГОСТ Р 34.10-2001
            XMLSignature xmlSignature = new XMLSignature(argDocument, "", XMLDSIG_SIGN_METHOD, XMLDSIG_DETACHED_TRANSFORM_METHOD);

            if (argSignatureId != null) {
                xmlSignature.setId(argSignatureId);
            }

            /* Определение правил работы с XML-документом и добавление в узел подписи этих правил */

            // создание узла преобразований <ds:Transforms> обрабатываемого XML-документа
            Transforms transforms = new Transforms(argDocument);

            // добавление в узел преобразований правил работы с документом
            if (enveloped) {
                transforms.addTransform(XMLDSIG_ENVELOPED_TRANSFORM_METHOD);
            }
            transforms.addTransform(XMLDSIG_DETACHED_TRANSFORM_METHOD);
            transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);

            // добавление в узел подписи ссылок (узла <ds:Reference>), определяющих правила работы с
            // XML-документом (обрабатывается текущий документ с заданными в узле <ds:Transforms> правилами
            // и заданным алгоритмом хеширования)
            String refURI = referenceURI;
            if (!refURI.isEmpty() && !refURI.startsWith("#")) {
                refURI = "#" + refURI;
            }
            xmlSignature.addDocument(refURI, transforms, DIGEST_METHOD);

            /* Создание подписи всего содержимого XML-документа на основе закрытого ключа, заданных правил и алгоритмов */

            // создание внутри узла подписи узла <ds:KeyInfo> информации об открытом ключе на основе
            // сертификата
            xmlSignature.addKeyInfo(argCertificate);

            // создание подписи XML-документа
            xmlSignature.sign(argPrivateKey);

            return xmlSignature.getElement();
        } catch (Exception e) {
            throw new SignatureProcessingException(e);
        }
    }

    // ================================ Проверка подписи XML

    @Override
    protected X509Certificate getCertificate(Element signatureElement) throws SignatureValidationException {
        try {
            // инициализация объекта проверки подписи
            XMLSignature signature = new XMLSignature(signatureElement, "");

            // чтение узла <ds:KeyInfo> информации об открытом ключе
            KeyInfo keyInfoFromSignature = signature.getKeyInfo();

            // чтение сертификата из узла информации об открытом ключе
            X509Certificate certificate = keyInfoFromSignature.getX509Certificate();

            // если сертификат найден, то осуществляется проверка
            // подписи на основе сертфиката
            if (certificate != null) {
                boolean signatureIsValid = signature.checkSignatureValue(certificate);
                if (!signatureIsValid) {
                    throw new SignatureValidationException(EDS_ERROR_SIGNATURE_INVALID);
                }
            }
            return certificate;
        } catch (XMLSecurityException e) {
            throw new SignatureValidationException(e);
        }
    }

    // ================================ PKCS7

    @Override
    public MessageDigest getDigest() throws SignatureProcessingException {
        try {
            return MessageDigest.getInstance(JCPCMSTools.GOST_DIGEST_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureProcessingException("Криптопровайдер не поддерживает алгоритм ГОСТ Р 34.11-94", e);
        }
    }

    @Override
    public byte[] signPKCS7Detached(byte[] argDigest, PrivateKey argPrivateKey, X509Certificate argUserCertificate) throws SignatureProcessingException {
        return PKCS7Tools.signPKCS7SunSecurity(argDigest, argPrivateKey, argUserCertificate);
    }

    @Override
    public X509Certificate validatePKCS7Signature(byte[] argDigest, byte[] argSignature) throws SignatureProcessingException, SignatureValidationException {
        return PKCS7Tools.verifyPKCS7BcProv(argDigest, argSignature);
    }
}
