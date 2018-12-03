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
    /// Instances of this class incapsulate a cryptographic header and encrypted value
    /// </summary>
    public class CryptographicValue<TAlgorithm> where TAlgorithm : SymmetricAlgorithm
    {
        /// <summary>
        /// Cryptographic Initialization Vector
        /// </summary>
        public byte[] Iv { get; set; }
        /// <summary>
        /// Encrypted value
        /// </summary>
        public byte[] Value { get; set; }

        private CryptographicValue()
        {

        }

        private CryptographicValue(byte[] iv, byte[] value)
        {
            Iv = iv;
            Value = value;
        }

        private CryptographicValue(byte[] value)
        {
            var algorithm = SymmetricAlgorithm.Create(typeof(TAlgorithm).Name);
            Iv = new byte[algorithm.BlockSize / 8];
            Buffer.BlockCopy(value, 0, Iv,  0, algorithm.BlockSize / 8);
            Value = (byte[])Array.CreateInstance(typeof(byte), value.Length - Iv.Length);
            Buffer.BlockCopy(value, Iv.Length, Value, 0, value.Length - Iv.Length);
        }

        /// <summary>
        /// Factory method creates an instance of <see cref="CryptographicValue{TAlgorithm}"/>
        /// </summary>
        /// <returns><see cref="CryptographicValue{TAlgorithm}"/></returns>
        public static CryptographicValue<TAlgorithm> Create()
        {
            return new CryptographicValue<TAlgorithm>();
        }

        /// <summary>
        /// Factory method creates an instance of <see cref="CryptographicValue{TAlgorithm}"/>
        /// </summary>
        /// <param name="iv">Initialization Vector</param>
        /// <param name="value">byte array containing an encrypted value</param>
        /// <returns><see cref="CryptographicValue{TAlgorithm}"/></returns>
        public static CryptographicValue<TAlgorithm> Create(byte[] iv, byte[] value)
        {
            return new CryptographicValue<TAlgorithm>(iv, value);
        }

        /// <summary>
        /// Factory method creates an instance of <see cref="CryptographicValue{TAlgorithm}"/>
        /// </summary>
        /// <param name="value">Binary value of a <see cref="CryptographicValue{TAlgorithm}"/></param>
        /// <returns><see cref="CryptographicValue{TAlgorithm}"/></returns>
        public static CryptographicValue<TAlgorithm> Create(byte[] value)
        {
            return new CryptographicValue<TAlgorithm>(value);
        }

        /// <summary>
        /// Returns binary value of a <see cref="CryptographicValue{TAlgorithm}"/>
        /// </summary>
        /// <returns>Binary value of a <see cref="CryptographicValue{TAlgorithm}"/></returns>
        public byte[] GetBinaryValue()
        {
            var temp = (byte[])Array.CreateInstance(typeof(byte), Iv.Length + Value.Length);
            Buffer.BlockCopy(Iv, 0, temp, 0, Iv.Length);
            Buffer.BlockCopy(Value, 0, temp, Iv.Length, Value.Length);
            return temp;
        }
    }
}