using database.Redis;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Newtonsoft.Json;
using StackExchange.Redis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using System.Xml.XPath;

namespace secure_reverse_proxy
{

    public class DataProtectionKey
    {
        /*
                 key["id"] = id.Value;
            key["activationDate"] = activationDate.Value;
            key["creationDate"] = creationDate.Value;
            key["expirationDate"] = expirationDate.Value;
            key["encryption"] = encryption.Attribute("algorithm").Value;
            key["validation"] = validation.Attribute("algorithm").Value;
            key["certificate"] = X509Certificate.Value;
            key["encryptedKey"] = cipherValue.Value;
            key["encryptedData"] = cipherValue2.Value;
         */
        public string Id { get; private set; }
        public DateTime ActivationDate { get; private set; }
        public DateTime CreationDate { get; private set; }
        public DateTime ExpirationDate { get; private set; }
        public string Encryption { get; private set; }
        public string Validation { get; private set; }
        public string Certificate { get; private set; }
        public string EncryptedKey { get; private set; }
        public string EncryptedData { get; private set; }
        public string EncryptionKey { get; private set;}

        public string XmlValue { get; private set; }

        public DataProtectionKey(string xmlValue)
        {
            XmlValue = xmlValue;
            Dictionary<string, string> key = new Dictionary<string, string>();
            XDocument doc = XDocument.Parse(xmlValue);
            XElement parentKey = doc.Root;
            XAttribute id = parentKey.Attribute("id");
            XElement activationDate = parentKey.Element("activationDate");
            XElement creationDate = parentKey.Element("creationDate");
            XElement expirationDate = parentKey.Element("expirationDate");

            XElement parentDescriptor2 = parentKey.Element("descriptor");
            XElement parentDescriptor = parentDescriptor2.Element("descriptor");

            XElement encryption = parentDescriptor.Element("encryption");
            XElement validation = parentDescriptor.Element("validation");
            XElement encryptedSecret = parentDescriptor.Element("{http://schemas.asp.net/2015/03/dataProtection}encryptedSecret");
            XElement encryptedData = encryptedSecret.Element("{http://www.w3.org/2001/04/xmlenc#}EncryptedData");
            XElement keyInfo = encryptedData.Element("{http://www.w3.org/2000/09/xmldsig#}KeyInfo");
            XElement encryptedKey = keyInfo.Element("{http://www.w3.org/2001/04/xmlenc#}EncryptedKey");


            XElement keyInfo2 = encryptedKey.Element("{http://www.w3.org/2000/09/xmldsig#}KeyInfo");
            XElement X509Data = keyInfo2.Element("{http://www.w3.org/2000/09/xmldsig#}X509Data");
            XElement X509Certificate = X509Data.Element("{http://www.w3.org/2000/09/xmldsig#}X509Certificate");
            XElement cipherData = encryptedKey.Element("{http://www.w3.org/2001/04/xmlenc#}CipherData");
            XElement cipherValue = cipherData.Element("{http://www.w3.org/2001/04/xmlenc#}CipherValue");
            XElement cipherData2 = encryptedData.Element("{http://www.w3.org/2001/04/xmlenc#}CipherData");
            XElement cipherValue2 = cipherData2.Element("{http://www.w3.org/2001/04/xmlenc#}CipherValue");

            Id = id.Value;
            ActivationDate = DateTime.Parse(activationDate.Value);
            CreationDate = DateTime.Parse(creationDate.Value);
            ExpirationDate = DateTime.Parse(expirationDate.Value);
            Encryption = encryption.Attribute("algorithm").Value;
            Validation= validation.Attribute("algorithm").Value;
            Certificate = X509Certificate.Value;
            EncryptedKey = cipherValue.Value;
            EncryptedData = cipherValue2.Value;
        }

    }

    public class CookieDecryptor
    {
        private readonly RedisHub _connection;
        private DataProtectionKey _activeKey;
        private X509Certificate2 _certificate;
        private byte[] _encryptionKey; 
        public CookieDecryptor (RedisHub connection, string certFileName, string password)
        {
            _certificate = new(Path.Join(Directory.GetCurrentDirectory(), certFileName),
                                            password);
            _connection = connection;
            GetKey();
        }

        public void Test ()
        {

        }
        public string DecryptBaseURL64String (string base64String)
        {
            return System.Text.Encoding.UTF8.GetString(DecryptAes256Cbc(Convert.FromBase64String(base64String.Replace('-', '+').Replace('_', '/'))));
        }
        private byte[] DecryptAes256Cbc(byte[] cipherText)
        {
            byte [] part1;
            byte [] part2;
            lock (_encryptionKey)
            {
                part1 = _encryptionKey[0..16];
                part2 = _encryptionKey[16..32];
            }
            // complete cipherText to multiple of 128 bits
            int cipherTextLength = cipherText.Length;
            int remainder = cipherTextLength % 16;
            if (remainder != 0)
            {
                cipherTextLength += 16 - remainder;
            }
            byte[] cipherTextComplete = new byte[cipherTextLength];
            Array.Copy(cipherText, cipherTextComplete, cipherText.Length);
            using (AesManaged aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.Zeros;
                aes.Key = part2;
                aes.IV = part1;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key,aes.IV);

                byte[] plainBytes = decryptor.TransformFinalBlock(cipherTextComplete, 0, cipherTextComplete.Length);

                return plainBytes;

            }
        }
        private void GetKey ()
        {
            //List<Dictionary<string, string>> keys = new ();
            List<DataProtectionKey> keys = new List<DataProtectionKey>();

            var returned = _connection.GetList("DataProtection-Keys");

            foreach (var returnValue in returned)
            {
                keys.Add(new DataProtectionKey(returnValue));
            }


            DateTime isNow = DateTime.Now;
            _activeKey = keys.Where(x => x.ActivationDate < isNow && x.ExpirationDate > isNow).FirstOrDefault();


            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(_activeKey.XmlValue);
            EncryptedXml exml = new EncryptedXml(xmlDoc);
            // Decrypt the XML document.
            exml.DecryptDocument();
            xmlDoc.Save("test.xml");

            X509Certificate2 keyCertificate = new X509Certificate2(Convert.FromBase64String(_activeKey.Certificate));
            if (keyCertificate.Thumbprint != _certificate.Thumbprint)
            {
                throw new Exception ("Certificates does not match");
            }
            byte[] dData = Convert.FromBase64String(_activeKey.EncryptedData.Replace('-', '+').Replace('_', '/'));
            byte[] dKey = Convert.FromBase64String(_activeKey.EncryptedKey.Replace('-', '+').Replace('_', '/'));

            _encryptionKey = _certificate.GetRSAPrivateKey().Decrypt(dKey, RSAEncryptionPadding.Pkcs1);

        }

    }



}
