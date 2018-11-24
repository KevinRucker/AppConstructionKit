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
        /// <see cref="CryptographicHeader{TAlgorithm}"/>
        /// </summary>
        public CryptographicHeader<TAlgorithm> Header { get; set; }
        /// <summary>
        /// Byte array containing an encrypted value
        /// </summary>
        public byte[] Value { get; set; }

        private CryptographicValue()
        {

        }

        private CryptographicValue(CryptographicHeader<TAlgorithm> header, byte[] value)
        {
            Header = header;
            Value = value;
        }

        private CryptographicValue(byte[] value)
        {
            var temp = (byte[])Array.CreateInstance(typeof(byte), CryptographicHeader<TAlgorithm>.Size());
            Buffer.BlockCopy(value, 0, temp, 0, CryptographicHeader<TAlgorithm>.Size());
            Header = CryptographicHeader<TAlgorithm>.Create(temp);
            Value = (byte[])Array.CreateInstance(typeof(byte), value.Length - CryptographicHeader<TAlgorithm>.Size());
            Buffer.BlockCopy(value, CryptographicHeader<TAlgorithm>.Size(), Value, 0, value.Length - CryptographicHeader<TAlgorithm>.Size());
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
        /// <param name="header"><see cref="CryptographicHeader{TAlgorithm}"/></param>
        /// <param name="value">byte array containing an encrypted value</param>
        /// <returns><see cref="CryptographicValue{TAlgorithm}"/></returns>
        public static CryptographicValue<TAlgorithm> Create(CryptographicHeader<TAlgorithm> header, byte[] value)
        {
            return new CryptographicValue<TAlgorithm>(header, value);
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
            var temp = (byte[])Array.CreateInstance(typeof(byte), CryptographicHeader<TAlgorithm>.Size() + Value.Length);
            Buffer.BlockCopy(Header.GetBinaryValue(), 0, temp, 0, CryptographicHeader<TAlgorithm>.Size());
            Buffer.BlockCopy(Value, 0, temp, CryptographicHeader<TAlgorithm>.Size(), Value.Length);
            return temp;
        }
    }
}