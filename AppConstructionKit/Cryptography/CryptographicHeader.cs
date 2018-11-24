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
using System.Security.Cryptography;

namespace AppConstructionKit.Cryptography
{
    /// <summary>
    /// Instances of this class encapsulate a Header for an encrypted value
    /// </summary>
    public class CryptographicHeader<TAlgorithm> where TAlgorithm : SymmetricAlgorithm
    {
        /// <summary>
        /// Initialization Vector
        /// </summary>
        public byte[] Iv { get; set; }
        /// <summary>
        /// Data unencrypted size
        /// </summary>
        public uint OriginalSize { get; set; } = 0;

        private CryptographicHeader()
        {
            var alg = SymmetricAlgorithm.Create(typeof(TAlgorithm).Name);
            Iv = (byte[])Array.CreateInstance(typeof(byte), alg.BlockSize / 8);
        }

        private CryptographicHeader(byte[] value)
        {
            var alg = SymmetricAlgorithm.Create(typeof(TAlgorithm).Name);
            Iv = (byte[])Array.CreateInstance(typeof(byte), alg.BlockSize / 8);
            Buffer.BlockCopy(value, 0, Iv, 0, Iv.Length);
            var tempValue = (byte[])Array.CreateInstance(typeof(byte), sizeof(ulong));
            Buffer.BlockCopy(value, Iv.Length, tempValue, 0, sizeof(uint));
            OriginalSize = BitConverter.ToUInt32(tempValue, 0);
        }

        /// <summary>
        /// Gets byte array containing header
        /// </summary>
        /// <returns><code>byte[]</code> containing <see cref="CryptographicHeader{TAlgorithm}"/> binary value</returns>
        public byte[] GetBinaryValue()
        {
            var tempValue = (byte[])Array.CreateInstance(typeof(byte), Size());
            Buffer.BlockCopy(Iv, 0, tempValue, 0, Iv.Length);
            var tempSize = BitConverter.GetBytes(OriginalSize);
            Buffer.BlockCopy(tempSize, 0, tempValue, Iv.Length, tempSize.Length);
            return tempValue;
        }

        /// <summary>
        /// Size in bytes of a <see cref="CryptographicHeader{TAlgorithm}"/>
        /// </summary>
        /// <returns>Size in bytes of the header</returns>
        public static int Size()
        {
            var alg = SymmetricAlgorithm.Create(typeof(TAlgorithm).Name);
            return (alg.BlockSize / 8) + sizeof(uint);
        }

        /// <summary>
        /// Factory method creates an instance of <see cref="CryptographicHeader{TAlgorithm}"/>
        /// </summary>
        /// <returns><see cref="CryptographicHeader{TAlgorithm}"/> instance</returns>
        public static CryptographicHeader<TAlgorithm> Create()
        {
            return new CryptographicHeader<TAlgorithm>();
        }

        /// <summary>
        /// Factory method creates an instance of <see cref="CryptographicHeader{TAlgorithm}"/>
        /// </summary>
        /// <param name="value"></param>
        /// <returns><see cref="CryptographicHeader{TAlgorithm}"/> instance</returns>
        public static CryptographicHeader<TAlgorithm> Create(byte[] value)
        {
            return new CryptographicHeader<TAlgorithm>(value);
        }
    }
}
