package ru.smevx.crypto.smev3.cms;

import ru.voskhod.crypto.DigitalSignatureFactory;
import ru.voskhod.crypto.exceptions.SignatureProcessingException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Класс {@link PKCS7Utils} реализующий методы формирования и проверки ЭП-СП сообщений c вложений в соответствии с п. 4.4 документа  "Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х".
 *
 * @author Vladislav Mostovoi
 * @see <a target="_blank" href="https://smev.gosuslugi.ru/portal/api/files/get/28834">Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х</a>
 * @since 2.0
 */
public class PKCS7Utils {

    private static final String JCP_PROVIDER_NAME = "JCP";

    /**
     * Медод формирование отсоедененной ЭП в формате PKCS#7 (в соответствии с МР СМЭВ 2.Х).
     *
     * @param privateKey приватный ключ, значение не может быть null.
     * @param cert       сертификат проверки ЭП, значение не может быть null.
     * @param data       подписываемые данные, значение не может быть null или пустым массивом.
     * @return в случае успешного выполнеия фозвращает byte[] отсоедененной подписи.
     */
    public static byte[] sign(final PrivateKey privateKey, final X509Certificate cert, final byte[] data) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Argument [privateKey] can't be null");
        }

        if (cert == null) {
            throw new IllegalArgumentException("Argument [cert] can't be null");
        }

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Argument [data] must be not empty");
        }

        try {
            DigitalSignatureFactory.init(JCP_PROVIDER_NAME);
            final byte[] digest = DigitalSignatureFactory.getDigitalSignatureProcessor().getDigest().digest(data);
            return DigitalSignatureFactory.getDigitalSignatureProcessor().signPKCS7Detached(digest, privateKey, cert);
        } catch (SignatureProcessingException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Медод проверки отсоедененной ЭП в формате PKCS#7 (в соответствии с МР СМЭВ 2.Х).
     *
     * @param sign данные отсоедененной подписи, значение не может быть null или пустым массивом.
     * @param data подписываемые данные, значение не может быть null или пустым массивом.
     * @throws Exception
     * @returnв true, если подпись для данных @data корректна, иначе false.
     */
    public static boolean validate(final byte[] sign, final byte[] data) throws Exception {
        if (sign == null || sign.length == 0) {
            throw new IllegalArgumentException("Argument [crypto] must be not empty");
        }

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Argument [data] must be not empty");
        }

        try {
            DigitalSignatureFactory.init(JCP_PROVIDER_NAME);
            final byte[] digest = DigitalSignatureFactory.getDigitalSignatureProcessor().getDigest().digest(data);
            final X509Certificate cert = DigitalSignatureFactory.getDigitalSignatureProcessor().validatePKCS7Signature(digest, sign);
            cert.checkValidity();

            return true;
        } catch (SignatureProcessingException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}