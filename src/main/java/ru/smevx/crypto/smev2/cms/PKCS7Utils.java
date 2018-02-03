package ru.smevx.crypto.smev2.cms;

import com.objsys.asn1j.runtime.*;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.*;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.params.OID;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Класс {@link PKCS7Utils} реализующий методы формирования и проверки ЭП-СП сообщений с вложениями в соответствии с п. 4.3 документа "Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х".
 *
 * @author Vladislav Mostovoi
 * @see <a target="_blank" href="https://smev.gosuslugi.ru/portal/api/files/get/28834">Методические рекомендации по работе с Единой системой межведомственного электронного взаимодействия 2.х</a>
 * @since 1.0
 */
public class PKCS7Utils {

    private static final String GOST_EL_SIGN_NAME = "GOST3411withGOST3410EL";
    private static final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";
    private static final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    private static final String DIGEST_OID = "1.2.643.2.2.9";
    private static final String SIGN_OID = "1.2.643.2.2.19";

    /**
     * Медод формирование отсоедененной ЭП в формате PKCS#7 (в соответствии с МР СМЭВ 2.Х).
     *
     * @param privateKey приватный ключ, значение не может быть null.
     * @param cert       сертификат проверки ЭП, значение не может быть null.
     * @param data       подписываемые данные, значение не может быть null или пустым массивом.
     * @return в случае успешного выполнеия фозвращает byte[] отсоедененной подписи.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CertificateEncodingException
     * @throws Asn1Exception
     * @throws IOException
     */
    public static byte[] sign(final PrivateKey privateKey, final X509Certificate cert, final byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateEncodingException, Asn1Exception, IOException {

        if (privateKey == null) {
            throw new IllegalArgumentException("Argument [privateKey] can't be null");
        }

        if (cert == null) {
            throw new IllegalArgumentException("Argument [cert] can't be null");
        }

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Argument [data] must be not empty");
        }

        // Получаем бинарную подпись длиной 64 байта.
        final Signature signature = Signature.getInstance(GOST_EL_SIGN_NAME);
        signature.initSign(privateKey);
        signature.update(data);

        final byte[] sign = signature.sign();

        // Формируем контекст подписи формата PKCS7.
        final ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(new OID(STR_CMS_OID_SIGNED).value);

        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(1);

        // Идентификатор алгоритма хеширования.
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);

        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(DIGEST_OID).value);
        a.parameters = new Asn1Null();

        cms.digestAlgorithms.elements[0] = a;
        // Т.к. подпись отсоединенная, то содержимое отсутствует.
        cms.encapContentInfo = new EncapsulatedContentInfo(new Asn1ObjectIdentifier(new OID(STR_CMS_OID_DATA).value), null);

        // Добавляем сертификат подписи.
        cms.certificates = new CertificateSet(1);
        final Certificate asnCertificate = new Certificate();
        final Asn1BerDecodeBuffer decodeBuffer = new Asn1BerDecodeBuffer(cert.getEncoded());
        asnCertificate.decode(decodeBuffer);

        cms.certificates.elements = new CertificateChoices[1];
        cms.certificates.elements[0] = new CertificateChoices();
        cms.certificates.elements[0].set_certificate(asnCertificate);

        // Добавялем информацию о подписанте.
        cms.signerInfos = new SignerInfos(1);
        cms.signerInfos.elements[0] = new SignerInfo();
        cms.signerInfos.elements[0].version = new CMSVersion(1);
        cms.signerInfos.elements[0].sid = new SignerIdentifier();

        final byte[] encodedName = cert.getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);

        final CertificateSerialNumber num = new CertificateSerialNumber(cert.getSerialNumber());

        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
        cms.signerInfos.elements[0].digestAlgorithm = new DigestAlgorithmIdentifier(new OID(DIGEST_OID).value);
        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signatureAlgorithm = new SignatureAlgorithmIdentifier(new OID(SIGN_OID).value);
        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signature = new SignatureValue(sign);

        // Получаем закодированную подпись.
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);

        return asnBuf.getMsgCopy();
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

        // Декодирование подписи формата PKCS7.
        final Asn1BerDecodeBuffer asnBuf = new Asn1BerDecodeBuffer(sign);
        final ContentInfo all = new ContentInfo();
        all.decode(asnBuf);

        // Проверка формата подписи.
        boolean supportedType = new OID(STR_CMS_OID_SIGNED).eq(all.contentType.value);
        if (!supportedType) {
            throw new Exception("Not supported");
        }

        final SignedData cms = (SignedData) all.content;
        if (cms.version.value != 1) {
            throw new Exception("Incorrect version");
        }

        boolean supportedData = new OID(STR_CMS_OID_DATA).eq(cms.encapContentInfo.eContentType.value);
        if (!supportedData) {
            throw new Exception("Nested not supported");
        }

        // Получение идентификатора алгоритма хеширования.
        OID digestOid = null;
        DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(new OID(DIGEST_OID).value);

        for (int i = 0; i < cms.digestAlgorithms.elements.length; i++) {
            if (a.algorithm.equals(cms.digestAlgorithms.elements[i].algorithm)) {
                digestOid = new OID(cms.digestAlgorithms.elements[i].algorithm.value);
                break;
            }
        }

        if (digestOid == null) {
            throw new Exception("Unknown digest");
        }

        // Поиск сертификата подписи.
        if (cms.certificates.elements.length == 0) {
            return false;
        }

        final Asn1BerEncodeBuffer encBuf = new Asn1BerEncodeBuffer();
        cms.certificates.elements[0].encode(encBuf);
        final byte[] certBytes = encBuf.getMsgCopy();

        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
        final X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);

        // Декодирование подписанта.
        final SignerInfo info = cms.signerInfos.elements[0];
        if (info.version.value != 1) {
            throw new Exception("Incorrect version");
        }

        if (!digestOid.equals(new OID(info.digestAlgorithm.algorithm.value))) {
            throw new Exception("Not signed on certificate");
        }

        final byte[] signValue = info.signature.value;

        // Проверка подписи.
        final Signature signature = Signature.getInstance(GOST_EL_SIGN_NAME);
        signature.initVerify(cert);
        signature.update(data);

        return signature.verify(signValue);
    }
}