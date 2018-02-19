package ru.smevx.crypto.smev3.xmldsig;

import org.apache.commons.lang3.StringUtils;
import org.apache.ws.security.util.UUIDGenerator;
import org.w3c.dom.Element;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import ru.voskhod.crypto.DigitalSignatureFactory;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Класс {@link XmlDSignUtils} реализующий методы формирования и проверки ЭП-СП сообщений без вложений в соответствии с п. 4.4 документа  "Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х".
 *
 * @author Vladislav Mostovoi
 * @see <a target="_blank" href="https://smev.gosuslugi.ru/portal/api/files/get/28834">Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х</a>
 * @since 2.0
 */
public class XmlDSignUtils {

    private static final String JCP_PROVIDER_NAME = "JCP";

    static {
        org.apache.xml.security.Init.init();
        // Инициализация КритптоПРО JCP сервис-провайдера.
        if (!JCPXMLDSigInit.isInitialized()) {
            JCPXMLDSigInit.init();
        }
    }

    /**
     * Медод формирование ЭП в формате XMLDSign для элемента DOM дерева (в соответствии с МР ЕСМЭВ 3.Х).
     *
     * @param privateKey приватный ключ, значение не может быть null.
     * @param cert       сертификат проверки ЭП, значение не может быть null.
     * @param data       DOM-элемент содержащий данные для подписи, значение не может быть пустым.
     * @return в случае успешного выполнеия DOM-элемент со значением подписи, иначе исключение.
     */
    public static Element sign(final PrivateKey privateKey, final X509Certificate cert, final Element data) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Argument [privateKey] can't be null");
        }

        if (cert == null) {
            throw new IllegalArgumentException("Argument [cert] can't be null");
        }

        if (data == null) {
            throw new IllegalArgumentException("Argument [data] can't be null");
        }

        try {
            DigitalSignatureFactory.init(JCP_PROVIDER_NAME);

            final String id = data.getAttribute("Id");
            if (StringUtils.isBlank(id)) {
                data.setAttribute("Id", UUIDGenerator.getUUID());
            }

            return signXMLDSigDetached(privateKey, cert, data, UUIDGenerator.getUUID().substring(0, 7));
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    private static Element signXMLDSigDetached(final PrivateKey privateKey, final X509Certificate cert, final Element element, final String signatureId) {
        try {
            return DigitalSignatureFactory.getDigitalSignatureProcessor().signXMLDSigDetached(element, signatureId, privateKey, cert);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Медод формирование ЭП в формате XMLDSign для элемента DOM дерева (в соответствии с МР ЕСМЭВ 3.Х).
     *
     * @param data      DOM-элемент содержащий данные для подписи, значение не может быть пустым.
     * @param signature DOM-элемент содержащий значение подписи, значение не может быть пустым.
     * @return true, если подпись корректна, иначе false.
     */
    public static boolean validate(final Element data, final Element signature) {
        if (data == null) {
            throw new IllegalArgumentException("Argument [signature] can't be null");
        }
        if (signature == null) {
            throw new IllegalArgumentException("Argument [signature] can't be null");
        }

        try {
            DigitalSignatureFactory.init(JCP_PROVIDER_NAME);

            final X509Certificate cert = DigitalSignatureFactory.getDigitalSignatureProcessor().validateXMLDSigDetachedSignature(data, signature);
            cert.checkValidity();

            return true;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
