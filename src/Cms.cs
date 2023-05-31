using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using LibCore.Security.Cryptography;

namespace LibCore.TestApp;

public static class Cms
{
    public static bool SignCmsDetached(byte[] bytesToHash, X509Certificate2 gostCert)
    {
        byte[] signature;
        // using (var gostCert = GostNonPersistCmsTests.GetGost2012_256Certificate())
        // {
        var contentInfo = new ContentInfo(bytesToHash);
        var signedCms = new SignedCms(contentInfo, true);
        CmsSigner cmsSigner = new CmsSigner(gostCert);
        signedCms.ComputeSignature(cmsSigner);
        signature = signedCms.Encode();
        Console.WriteLine($"CMS Sign: {Convert.ToBase64String(signature)}");
        //}

        // Создаем объект ContentInfo по сообщению.
        // Это необходимо для создания объекта SignedCms.
        ContentInfo contentInfoVerify = new ContentInfo(bytesToHash);

        // Создаем SignedCms для декодирования и проверки.
        SignedCms signedCmsVerify = new SignedCms(contentInfoVerify, true);

        // Декодируем подпись
        signedCmsVerify.Decode(signature);
        try
        {
            // Проверяем подпись
            signedCmsVerify.CheckSignature(true);
        }
        catch
        {
            return false;
        }

        return true;
    }


    public static bool SignCms(byte[] bytesToHash, X509Certificate2 gostCert)
    {
        byte[] signature;
        // using (var gostCert = GostNonPersistCmsTests.GetGost2012_256Certificate())
        // {
        var contentInfo = new ContentInfo(bytesToHash);
        var signedCms = new SignedCms(contentInfo, false);
        CmsSigner cmsSigner = new CmsSigner(gostCert);
        signedCms.ComputeSignature(cmsSigner);
        signature = signedCms.Encode();
        Console.WriteLine($"CMS Sign: {Convert.ToBase64String(signature)}");
        //}

        // Создаем SignedCms для декодирования и проверки.
        SignedCms signedCmsVerify = new SignedCms();

        // Декодируем подпись
        signedCmsVerify.Decode(signature);

        // Проверяем подпись
        try
        {
            signedCmsVerify.CheckSignature(true);
        }
        catch
        {
            return false;
        }

        return true;
    }

    public static byte[] EncryptCms(byte[] dataToEncrypt, X509Certificate2 gostCert)
    {
        var ci = new ContentInfo(dataToEncrypt);

        // var publicKey = gostCert.PublicKey.Key
        //     as Gost3410_2012_512CryptoServiceProvider;

        var oid = gostCert.PublicKey.Oid;

        var ec = new CpEnvelopedCms(ci);

        var recipients = new CmsRecipient(gostCert);

        ec.Encrypt(recipients);

        var encryptedData = ec.Encode();
        return encryptedData;
    }

    public static byte[] DecryptCms(byte[] encryptedData, X509Certificate2 gostCert)
    {
        var oid = gostCert.PublicKey.Oid;
        //var ec = new CpEnvelopedCms(null, new AlgorithmIdentifier(oid));
        var ec = new CpEnvelopedCms();
        ec.Decode(encryptedData);

        ec.Decrypt(new X509Certificate2Collection(gostCert));
        return ec.ContentInfo.Content;
    }


}
