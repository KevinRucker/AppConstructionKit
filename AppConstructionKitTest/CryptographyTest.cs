using System.Text;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using AppConstructionKit.Cryptography;

namespace AppConstructionKitTest
{
    [TestClass]
    public class CryptographyTest
    {
        private readonly string testValue = "Now is the time for all good men to come to the aid of their country. 0123456789";
        private readonly string passPhrase = "The quick brown fox jumped over the lazy dog's back. 0123456879";

        [TestMethod]
        public void EncryptDecryptString()
        {
            var crypto = new SymmetricEncryptionProvider<Aes>();
            var encrypted = crypto.EncryptString(testValue, passPhrase);
            var decrypted = crypto.DecryptString(encrypted, passPhrase);
            Assert.AreEqual(testValue, decrypted);
        }

        [TestMethod]
        public void EncryptDecryptStringFail()
        {
            var crypto = new SymmetricEncryptionProvider<Aes>();
            var encrypted = crypto.EncryptString(passPhrase, testValue);
            Assert.ThrowsException<CryptographicException>(
                () => crypto.DecryptString(encrypted, "Different passphrase"));
        }

        [TestMethod]
        public void EncryptDecryptBytes()
        {
            var crypto = new SymmetricEncryptionProvider<Aes>();
            var key = CryptographicDigest.Create().GetDigest(passPhrase, 32);
            var encrypted = crypto.EncryptBytes(new UTF8Encoding().GetBytes(testValue), key);
            var decrypted = new UTF8Encoding().GetString(crypto.DecryptBytes(encrypted, key));
            Assert.AreEqual(testValue, decrypted);
        }

        [TestMethod]
        public void EncryptDecryptBytesFail()
        {
            var crypto = new SymmetricEncryptionProvider<Aes>();
            var key = CryptographicDigest.Create().GetDigest(passPhrase, 32);
            var differentKey = CryptographicDigest.Create().GetDigest("Different passphrase", 32);
            var encrypted = crypto.EncryptBytes(new UTF8Encoding().GetBytes(testValue), key);
            Assert.ThrowsException<CryptographicException>(
                () => new UTF8Encoding().GetString(crypto.DecryptBytes(encrypted, differentKey)));
        }
    }
}