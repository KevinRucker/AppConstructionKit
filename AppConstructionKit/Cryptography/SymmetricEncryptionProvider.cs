// Author: Kevin Rucker
// License: BSD 3-Clause
// Copyright (c) 2018, Kevin Rucker
// All rights reserved.

// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// Disclaimer:
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AppConstructionKit.Cryptography
{
    /// <summary>
    /// Instances of this class encapsulate symmetric encryption functionality
    /// </summary>
    /// <typeparam name="TAlgorithm">The symmetric algorithm to use</typeparam>
    public class SymmetricEncryptionProvider<TAlgorithm> where TAlgorithm : SymmetricAlgorithm
    {
        private SymmetricEncryptionProvider()
        {

        }

        /// <summary>
        /// Factory method creates an instance of <see cref="SymmetricEncryptionProvider{TAlgorithm}"/>
        /// </summary>
        /// <returns></returns>
        public static SymmetricEncryptionProvider<TAlgorithm> Create()
        {
            return new SymmetricEncryptionProvider<TAlgorithm>();
        }

        /// <summary>
        /// Encrypt string
        /// </summary>
        /// <param name="value">Value to encrypt</param>
        /// <param name="passPhrase">Pass phrase to generate cryptographic key</param>
        /// <returns>base64 encoded string containing encrypted value</returns>
        public string EncryptString(string value, string passPhrase)
        {
            var plainValuee = new UTF8Encoding().GetBytes(value);
            var key = CryptographicDigest.Create().GetDigest(passPhrase, 32);

            return Convert.ToBase64String(EncryptBytes(plainValuee, key));
        }

        /// <summary>
        /// Encrypt byte array
        /// </summary>
        /// <param name="value">Value to encrypt</param>
        /// <param name="key">Cryptographic key</param>
        /// <returns>Byte array containing Initialization Vector and encrypted value</returns>
        public byte[] EncryptBytes(byte[] value, byte[] key)
        {
            var algorithm = SymmetricAlgorithm.Create(typeof(TAlgorithm).Name);

            if (!algorithm.ValidKeySize(key.Length * 8))
            {
                throw new ArgumentException("Invalid key size for specified symmetric algorithm [" + typeof(TAlgorithm).Name + "].");
            }

            algorithm.GenerateIV();
            algorithm.Key = key;

            using (var encryptor = algorithm.CreateEncryptor())
            {
                using (var msEncrypt = new MemoryStream())
                {
                    using (var encryptStream = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var plainStream = new MemoryStream(value))
                        {
                            plainStream.CopyTo(encryptStream);
                            encryptStream.FlushFinalBlock();
                            var encrypted = CryptographicValue<TAlgorithm>.Create(algorithm.IV, msEncrypt.ToArray());
                            algorithm.Clear();
                            return encrypted.GetBinaryValue();
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Decrypt base64 encoded string
        /// </summary>
        /// <param name="b64Value">base64 encoded value to decrypt</param>
        /// <param name="passPhrase"></param>
        /// <returns><code>System.String</code> containing decrypted value</returns>
        public string DecryptString(string b64Value, string passPhrase)
        {
            var encrypted = Convert.FromBase64String(b64Value);
            var key = CryptographicDigest.Create().GetDigest(passPhrase, 32);

            return new UTF8Encoding().GetString(DecryptBytes(encrypted, key));
        }

        /// <summary>
        /// Decrypt byte array
        /// </summary>
        /// <param name="value">Value to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <returns><code>byte[]</code> containing decrypted data</returns>
        public byte[] DecryptBytes(byte[] value, byte[] key)
        {
            var algorithm = SymmetricAlgorithm.Create(typeof(TAlgorithm).Name);

            if (!algorithm.ValidKeySize(key.Length * 8))
            {
                throw new ArgumentException("Invalid key size for specified symmetric algorithm [" + typeof(TAlgorithm).Name + "].");
            }

            var cryptoValue = CryptographicValue<TAlgorithm>.Create(value);
            using (var decryptor = algorithm.CreateDecryptor(key, cryptoValue.Iv))
            {
                using (var msDecrypt = new MemoryStream(cryptoValue.Value))
                {
                    using (var decryptStream = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var resultStream = new MemoryStream())
                        {
                            decryptStream.CopyTo(resultStream);
                            algorithm.Clear();
                            return resultStream.ToArray();
                        }
                    }
                }
            }
        }
    }
}
