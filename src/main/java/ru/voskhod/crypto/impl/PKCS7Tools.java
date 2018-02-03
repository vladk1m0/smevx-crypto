package ru.voskhod.crypto.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import ru.voskhod.crypto.exceptions.SignatureProcessingException;
import ru.voskhod.crypto.exceptions.SignatureValidationException;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@SuppressWarnings("unchecked")
public class PKCS7Tools {

    public static byte[] signPKCS7SunSecurity(byte[] digestedContent, PrivateKey privateKey, X509Certificate certificate) throws SignatureProcessingException {
        try {

            // Данные для подписи.
            PKCS9Attribute[] authenticatedAttributeList = {
                    new PKCS9Attribute(PKCS9Attribute.CONTENT_TYPE_OID, sun.security.pkcs.ContentInfo.DATA_OID),
                    new PKCS9Attribute(PKCS9Attribute.SIGNING_TIME_OID, new java.util.Date()),
                    new PKCS9Attribute(PKCS9Attribute.MESSAGE_DIGEST_OID, digestedContent)
            };
            PKCS9Attributes authenticatedAttributes = new PKCS9Attributes(authenticatedAttributeList);
            // Подписываем.
            byte[] signedAttributes = sign(privateKey, authenticatedAttributes.getDerEncoding());

            // SignerInfo.
            java.math.BigInteger serial = certificate.getSerialNumber();
            sun.security.pkcs.SignerInfo si = new sun.security.pkcs.SignerInfo(
                    new X500Name(certificate.getIssuerDN().getName()), // X500Name issuerName,
                    serial, //x509.getSerialNumber(), // BigInteger serial,
                    AlgorithmId.get(JCPCMSTools.DIGEST_OID), //JCPCMSTools.GOST_DIGEST_NAME), // AlgorithmId digestAlgorithmId,
                    authenticatedAttributes, // PKCS9Attributes authenticatedAttributes,
                    new AlgorithmId(new ObjectIdentifier(JCPCMSTools.SIGN_OID)), // AlgorithmId digestEncryptionAlgorithmId,
                    signedAttributes, // byte[] encryptedDigest,
                    null); // PKCS9Attributes unauthenticatedAttributes) {
            sun.security.pkcs.SignerInfo[] signerInfos = {si};

            // Сертификат.
            X509Certificate[] certificates = {certificate};

            // Алгоритм подписи.
            AlgorithmId[] digestAlgorithmIds = {AlgorithmId.get(JCPCMSTools.DIGEST_OID)};

            sun.security.pkcs.ContentInfo contentInfo = new sun.security.pkcs.ContentInfo(sun.security.pkcs.ContentInfo.DATA_OID, null);

            // Собираем все вместе и пишем в стрим.
            PKCS7 p7 = new PKCS7(digestAlgorithmIds, contentInfo, certificates, signerInfos);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            p7.encodeSignedData(bos);

            return bos.toByteArray();

        } catch (Exception e) {
            throw new SignatureProcessingException(e);
        }
    }

    private static byte[] sign(PrivateKey key, byte[] data) throws SignatureProcessingException {
        try {
            Signature signer = Signature.getInstance(JCPCMSTools.GOST_EL_SIGN_NAME);
            signer.initSign(key);
            signer.update(data);
            return signer.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            throw new SignatureProcessingException(ex);
        }
    }

    public static X509Certificate verifyPKCS7BcProv(byte[] argDigestedData, byte[] signedDataByteArray) throws SignatureValidationException {
        try {

            // Загоняем подписанные данные в объект.
            CMSSignedData signedData = new CMSSignedData(signedDataByteArray);
            // Создаем фабрику сертификатов.
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            // Вытягиваем все сертификаты.
            List<X509Certificate> certificates = new ArrayList<>();
            for (X509CertificateHolder holder : (Collection<X509CertificateHolder>) signedData.getCertificates().getMatches(null)) {
                certificates.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(holder.getEncoded())));
            }

            // Сертификат, который будет возвращен из метода
            X509Certificate certificateToReturn = null;

            // Листаем подписантов.
            SignerInformationStore signers = signedData.getSignerInfos();
            for (SignerInformation signer : (Collection<SignerInformation>) signers.getSigners()) {

                // Проверяем что подписанные данные есть.
                if (signer.getSignedAttributes() == null) {
                    throw new SignatureValidationException("Подпись в формате PKCS#7 не содержет подписанных данных!");
                }
                // Извлекаем дайджест, использованный при подписи, сравниваем с актуальным.
                org.bouncycastle.asn1.cms.Attribute attribute = signer.getSignedAttributes().get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4"));
                DEROctetString oct = (DEROctetString) attribute.getAttributeValues()[0];
                byte[] dig = oct.getOctets();
                if (!java.util.Arrays.equals(argDigestedData, dig)) {
                    throw new SignatureValidationException("Дайджест не прошел проверку!");
                }

                // Листаем сертификаты.
                byte[] signatureAsByteArray = signer.getSignature();
                for (X509Certificate providedCertificate : certificates) {
                    // Каждый раз обновляем поток isCheckData.
                    InputStream isCheckData = new ByteArrayInputStream(signer.getEncodedSignedAttributes());
                    boolean signatureIsVerified = checkOnCert(isCheckData, providedCertificate, signatureAsByteArray);
                    // TODO Loskutov Интересно почиму возвращается только первый удачно проверенный сертификат?
                    if (signatureIsVerified && certificateToReturn == null) {
                        certificateToReturn = providedCertificate;
                    }
                }
            }

            if (certificateToReturn != null) {
                return certificateToReturn;
            } else {
                throw new SignatureValidationException("Подпись не прошла проверку по сертификату.");
            }
        } catch (SignatureValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureValidationException(e);
        }
    }

    public static boolean checkOnCert(InputStream isCheckData, X509Certificate certificate, byte[] argSignatureAsByteArray) throws SignatureProcessingException {
        try {
            Signature signature;
            try {
                signature = Signature.getInstance(JCPCMSTools.GOST_EL_SIGN_NAME);
                signature.initVerify(certificate);
            } catch (InvalidKeyException e) {
                throw new SignatureProcessingException("Открытый ключ поврежден.", e);
            } catch (NoSuchAlgorithmException e) {
                throw new SignatureProcessingException("Не поддерживается алгоритм подписи " + JCPCMSTools.GOST_EL_SIGN_NAME + ". Убедитесь, что установлен нужный криптопровайдер.", e);
            }

            try {
                byte[] localBuffer = new byte[4096];
                for (int readBytesCount; (readBytesCount = isCheckData.read(localBuffer)) > 0; ) {
                    signature.update(localBuffer, 0, readBytesCount);
                }
            } catch (SignatureException e) {
                throw new SignatureProcessingException("Сбой при генерации message digest.", e);
            } catch (IOException e) {
                throw new SignatureProcessingException("Невозможно прочитать подписываемые данные из потока.", e);
            }

            try {
                return signature.verify(argSignatureAsByteArray);
            } catch (SignatureException e) {
                throw new SignatureProcessingException("Сбой на фазе верификации ЭЦП.", e);
            }

        } finally {
            try {
                isCheckData.close();
            } catch (IOException e) {
                // TODO Loskutov Нужен ворнинг.
                // Ignore.
            }
        }
    }
}
