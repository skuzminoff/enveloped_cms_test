// See https://aka.ms/new-console-template for more information

using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LibCore.Security.Cryptography;
using LibCore.Security.Cryptography.X509Certificates;
using LibCore.TestApp;

Console.WriteLine("Init libcore");
var signed1 = new CmsSigner();


LibCore.Initializer.Initialize();

Console.WriteLine("Init libcore finished");

var pin = "";
var pfxfilename = "testcert.pfx";

var pfxContent = File.ReadAllBytes(pfxfilename);

using (var gostCert = X509CertificateExtensions.Create(
           pfxContent,
           pin,
           CpX509KeyStorageFlags.CspNoPersistKeySet))
{
    Console.WriteLine($"Certificate:{gostCert.Thumbprint}");

    var testPlainData = "Hello, World!!1";
    var encryptedData = Cms.EncryptCms(Encoding.UTF8.GetBytes(testPlainData), gostCert);
    Console.WriteLine(Convert.ToBase64String(encryptedData));

    try
    {
        var decryptedData = Cms.DecryptCms(encryptedData, gostCert);
        Console.WriteLine(Convert.ToBase64String(decryptedData));
        Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
    }
    catch (Exception e)
    {
        Console.WriteLine(e);
    }
}

