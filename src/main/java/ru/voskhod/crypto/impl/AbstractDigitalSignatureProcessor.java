package ru.voskhod.crypto.impl;

import org.w3c.dom.*;
import ru.voskhod.crypto.DigitalSignatureProcessor;
import ru.voskhod.crypto.PipeInputStream;
import ru.voskhod.crypto.exceptions.DocumentIsNotSignedException;
import ru.voskhod.crypto.exceptions.SignatureProcessingException;
import ru.voskhod.crypto.exceptions.SignatureValidationException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractDigitalSignatureProcessor implements DigitalSignatureProcessor {

    protected static final String EDS_ERROR_PUBLIC_KEY_IS_NOT_FOUND = "Нет информации об открытом ключе. Проверка не может быть осуществлена.";
    protected static final ThreadLocal<DocumentBuilder> documentBuilder = new ThreadLocal<DocumentBuilder>() {
        @Override
        protected DocumentBuilder initialValue() {
            DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
            domFactory.setNamespaceAware(true);
            try {
                return domFactory.newDocumentBuilder();
            } catch (ParserConfigurationException e) {
                throw new RuntimeException(e);
            }
        }
    };
    private static final int BUFFER_SIZE = 4096;
    private static final ThreadLocal<byte[]> buffer = new ThreadLocal<byte[]>() {
        @Override
        protected byte[] initialValue() {
            return new byte[BUFFER_SIZE];
        }
    };

    // ================================ Подпись XML

    // TODO обработка случаев, когда xmldsig пространство имён имеет префикс, отличный от ds:
    protected static Element findSignatureElement(Node signedDoc) throws DocumentIsNotSignedException, DOMException, XPathExpressionException {
        // выбор из прочитанного содержимого пространства имени узла подписи <ds:Signature>
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(new SignatureNamespaceContext());
        XPathExpression sigXP = xpath.compile("//ds:Signature[1]");
        Element sigElement = (Element) sigXP.evaluate(signedDoc, XPathConstants.NODE);

        if (sigElement == null) {
            throw new DocumentIsNotSignedException();
        }
        return sigElement;
    }

    public static byte[] calculateDigest(InputStream isdata, MessageDigest digest) throws SignatureProcessingException {
        try {
            byte[] localBuffer = buffer.get();
            try {
                int readBytesCount;
                while ((readBytesCount = isdata.read(localBuffer)) >= 0) {
                    digest.update(localBuffer, 0, readBytesCount);
                }
            } catch (IOException e) {
                throw new SignatureProcessingException("Сбой на фазе генерации message digest.", e);
            }
            return digest.digest();
        } finally {
            try {
                isdata.close();
            } catch (IOException e) {
                e.printStackTrace(); // todo: warning???
            }
        }
    }

    @Override
    public void signXMLDSigEnveloped(Element argDocumentFragment2Sign, PrivateKey argPrivateKey, X509Certificate argCertificate) throws SignatureProcessingException {
        signXMLDSigEnveloped(argDocumentFragment2Sign, null, SIG_POSITION.FIRST, null, argPrivateKey, argCertificate);
    }

    @Override
    public void signXMLDSigEnveloped(Element argDocumentRoot, String argXPath2Element2Sign, SIG_POSITION argSignaturePosition, String argSignatureId, PrivateKey argPrivateKey, X509Certificate argCertificate) throws SignatureProcessingException {
        // Готовим данные.
        Document documentToBeSigned;
        Element elementToBeSigned;
        if (argDocumentRoot.getParentNode() == argDocumentRoot.getOwnerDocument() && argXPath2Element2Sign == null) {
            documentToBeSigned = argDocumentRoot.getOwnerDocument();
            elementToBeSigned = argDocumentRoot;
        } else if (argXPath2Element2Sign == null) {
            documentToBeSigned = documentBuilder.get().newDocument();
            documentToBeSigned.appendChild(documentToBeSigned.importNode(argDocumentRoot, true));
            elementToBeSigned = argDocumentRoot;
        } else {
            XPathFactory factory = XPathFactory.newInstance();
            XPath xpath = factory.newXPath();
            try {
                XPathExpression sigXPath = xpath.compile(argXPath2Element2Sign);
                elementToBeSigned = (Element) sigXPath.evaluate(argDocumentRoot, XPathConstants.NODE);
            } catch (XPathExpressionException e) {
                throw new SignatureProcessingException("Невозможно найти элемент, который требуется подписать.", e);
            }
            documentToBeSigned = documentBuilder.get().newDocument();
            documentToBeSigned.appendChild(documentToBeSigned.importNode(elementToBeSigned, true));
        }

        // Подписываем.
        Node signature = signXMLDSig(documentToBeSigned, null, argPrivateKey, argCertificate, argSignatureId, true);

        // Добавляем подпись.
        if (argDocumentRoot.getOwnerDocument() != signature.getOwnerDocument()) {
            signature = argDocumentRoot.getOwnerDocument().importNode(signature, true);
        }
        if (argSignaturePosition.equals(SIG_POSITION.LAST)) {
            // В конце.
            elementToBeSigned.appendChild(signature);
        } else {
            // В начало.
            Node firstNode = elementToBeSigned.getFirstChild();
            elementToBeSigned.insertBefore(signature, firstNode);
        }
    }

    // ================================ Проверка подписи XML

    @Override
    public Element signXMLDSigDetached(Element argDocumentFragment2Sign, String argSignatureId, PrivateKey argPrivateKey, X509Certificate argCertificate) throws SignatureProcessingException {
        Element signature = signXMLDSig(argDocumentFragment2Sign.getOwnerDocument(), argDocumentFragment2Sign, argPrivateKey, argCertificate, argSignatureId, false);
        if (signature.getOwnerDocument() == argDocumentFragment2Sign.getOwnerDocument()) {
            return signature;
        } else {
            return (Element) argDocumentFragment2Sign.getOwnerDocument().importNode(signature, true);
        }
    }

    protected abstract Element signXMLDSig(Document argDocument, Element element2Sign, PrivateKey argPrivateKey, X509Certificate argCertificate, String argSignatureId, boolean enveloped) throws SignatureProcessingException;

    @Override
    public X509Certificate validateXMLDSigEnvelopedSignature(Element signedContent) throws SignatureProcessingException, SignatureValidationException, DocumentIsNotSignedException {
        return validateXMLDSig(signedContent, null);
    }

    @Override
    public X509Certificate validateXMLDSigDetachedSignature(Element signedContent, Element detachedSignature) throws SignatureProcessingException, SignatureValidationException {
        Document tmpDocContent = documentBuilder.get().newDocument();
        Element cutContent = (Element) tmpDocContent.importNode(signedContent, true);
        tmpDocContent.appendChild(cutContent);
        Attr idAttribute = cutContent.getAttributeNode("Id");
        if (idAttribute != null) {
            cutContent.setIdAttributeNode(idAttribute, true);
        }
        Document tmpDocSignature = documentBuilder.get().newDocument();
        Element cutSignature = (Element) tmpDocSignature.importNode(detachedSignature, true);
        tmpDocSignature.appendChild(cutSignature);
        try {
            return validateXMLDSig(cutContent, cutSignature);
        } catch (DocumentIsNotSignedException e) {
            throw new SignatureValidationException(e);
        }
    }

    protected X509Certificate validateXMLDSig(Element argSignedContent, Element argSignatureElement) throws SignatureValidationException, DocumentIsNotSignedException {
        if (argSignedContent == null) {
            throw new DocumentIsNotSignedException("Подписанный XML-фрагмент не передан.");
        }

        if (argSignatureElement != null) {
            if (!SignatureNamespaceContext.XMLDSIG_NS.equals(argSignatureElement.getNamespaceURI()) || !"Signature".equals(argSignatureElement.getLocalName())) {
                throw new DocumentIsNotSignedException("Корневой элемент detached-подписи имеет полное имя, отличное от {http://www.w3.org/2000/09/xmldsig#}.Signature");
            }
        }

        try {
            Element signatureElement = argSignatureElement != null ? argSignatureElement : findSignatureElement(argSignedContent);
            if (signatureElement == null) {
                throw new DocumentIsNotSignedException("Не найден элемент {http://www.w3.org/2000/09/xmldsig#}.Signature");
            }

            NodeList nl = signatureElement.getElementsByTagNameNS(SignatureNamespaceContext.XMLDSIG_NS, "Reference");
            boolean emptyRefURI = false;
            if (nl.getLength() > 0) {
                Element ref = (Element) nl.item(0);
                Attr uri = ref.getAttributeNode("URI");
                emptyRefURI = (uri == null || "".equals(uri.getNodeValue()));
            }

            if (argSignatureElement != null && argSignedContent.getOwnerDocument() != argSignatureElement.getOwnerDocument()) {
                // Если подпись передана явным образом, и она не находится в том же DOM-дереве, что и подписанный контент,
                // нужно поместить их в общее DOM-дерево. Это нужно потому, что Santuario валидирует подпись только в общем документе с контентом.
                Document tmpDocument = documentBuilder.get().newDocument();
                Element tmpDocumentRootElement = (Element) tmpDocument.appendChild(tmpDocument.createElement("root_validator"));
                signatureElement = (Element) tmpDocumentRootElement.appendChild(tmpDocument.importNode(argSignatureElement, true));
                Element signedContent = (Element) tmpDocumentRootElement.appendChild(tmpDocument.importNode(argSignedContent, true));

                //Fix see description https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=5640
                Attr attributeNode = signedContent.getAttributeNode("Id");
                signedContent.setIdAttributeNode(attributeNode, true);
                tmpDocument.normalizeDocument();

            } else if (argSignatureElement == null && (signatureElement.getParentNode() != argSignedContent || emptyRefURI)) {
                // Если подпись - enveloped, и подписанный контент находится не в корне XML-документа, Santuario
                // может неправильно понимать, на каком фрагменте проверять подпись.
                // Поэтому подписанный фрагмент выносим в отдельный документ.
                // При этом считаем, что подпись находится сразу под подписанным фрагментом.
                // TODO сделать более обобщённую обработку.
                Document tmpDocument = documentBuilder.get().newDocument();
                Node importedSignatureParent = tmpDocument.importNode(signatureElement.getParentNode(), true);
                tmpDocument.appendChild(importedSignatureParent);
                tmpDocument.normalizeDocument();
                signatureElement = findSignatureElement(tmpDocument);
            }

            /* Проверка подписи XML-документа на основе информации об открытом ключе, хранящейся в XML-документе */
            // чтение сертификата из узла информации об открытом ключе
            return getCertificate(signatureElement);
        } catch (DOMException | XPathExpressionException e) {
            throw new SignatureValidationException(e);
        }
    }

    @Override
    public List<ValidationResult> validateXMLDSigEnvelopedAllSignature(Element xmlWithSignature) throws SignatureValidationException {
        if (xmlWithSignature == null) {
            throw new SignatureValidationException("Подписанный XML-фрагмент не передан.");
        }

        try {
            // Ищем элементы подписи.
            XPathFactory factory = XPathFactory.newInstance();
            XPath xpath = factory.newXPath();
            xpath.setNamespaceContext(new SignatureNamespaceContext());
            // TODO Losktuov Можно наверно скомпилированный xPath закэшировать.
            NodeList nodeList = (NodeList) xpath.compile("//ds:Signature").evaluate(xmlWithSignature, XPathConstants.NODESET);

            // Если ничего не найдено - ошибка.
            if (nodeList.getLength() == 0) {
                throw new SignatureValidationException("Не найден элемент {" + SignatureNamespaceContext.XMLDSIG_NS + "}.Signature!");
            }

            // Сюда будем складывать результаты проверок подписей.
            List<ValidationResult> validationResults = new ArrayList<>();

            // Поехали проверять подписи.
            for (int i = 0; i < nodeList.getLength(); i++) {
                ValidationResult validationResult = new ValidationResult();
                try {
                    // Чтение сертификата из узла информации об открытом ключе
                    X509Certificate certificate = getCertificate((Element) nodeList.item(i));

                    // Если сертификат найден - проверяем.
                    if (certificate != null) {
                        validationResult.setCertificate(certificate);
                    } else {
                        throw new SignatureValidationException(EDS_ERROR_PUBLIC_KEY_IS_NOT_FOUND);
                    }
                    validationResult.setValid(true);
                } catch (Exception e) {
                    validationResult.setValid(false);
                    validationResult.setError(e.getMessage());
                    validationResult.setException(e);
                }
                validationResults.add(validationResult);
            }

            return validationResults;
        } catch (DOMException | XPathExpressionException e) {
            throw new SignatureValidationException(e);
        }
    }

    // ================================ PKCS7

    protected abstract X509Certificate getCertificate(Element signatureElement) throws SignatureValidationException;

    @Override
    public PipeInputStream getPipeStream(InputStream argStreamToBeWrapped) throws SignatureProcessingException {
        return new PipeInputStream(argStreamToBeWrapped, getDigest());
    }

    @Override
    public byte[] signPKCS7Detached(InputStream argContent2Sign, PrivateKey argPrivateKey, X509Certificate argUserCertificate) throws SignatureProcessingException {
        // Вычисляем дайджест.
        byte[] digestedContent = calculateDigest(argContent2Sign, getDigest());
        // Подписываем.
        return signPKCS7Detached(digestedContent, argPrivateKey, argUserCertificate);
    }

    @Override
    public X509Certificate validatePKCS7Signature(InputStream argSignedContent, byte[] signature) throws SignatureProcessingException, SignatureValidationException {
        // Считаем дайджест.
        byte[] digestedContent = calculateDigest(argSignedContent, getDigest());
        // Проверяем.
        return validatePKCS7Signature(digestedContent, signature);
    }
}
