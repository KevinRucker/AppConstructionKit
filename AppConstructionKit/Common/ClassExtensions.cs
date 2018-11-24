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
using System.Data.SqlTypes;
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace AppConstructionKit.Common
{
    /// <summary>
    /// Common class extensions
    /// </summary>
    public static class ClassExtensions
    {
        /// <summary>
        /// Function to create and return a binary buffer
        /// </summary>
        public static Func<int, byte[]> CreateBuffer = x => (byte[])Array.CreateInstance(typeof(byte), x);

        #region DateTime Extensions

        /// <summary>
        /// <see cref="DateTime"/> extension: Verify <see cref="DateTime"/> is valid for Microsoft SQL Server
        /// </summary>
        /// <param name="dt">The <see cref="DateTime"/> to check</param>
        /// <returns><c>true</c> if the <see cref="DateTime"/> is valid; otherwise <c>false</c></returns>
        public static bool IsSQLValid(this DateTime dt)
        {
            return dt.IsBetween(
                (DateTime)SqlDateTime.MinValue,
                (DateTime)SqlDateTime.MaxValue, 
                true);
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Get <see cref="DateTime"/> as Julian Date (Day of year)
        /// </summary>
        /// <param name="dt">The <see cref="DateTime"/> to convert</param>
        /// <returns>Julian calendar date</returns>
        public static int JulianDate(this DateTime dt)
        {
            var ci = CultureInfo.CurrentCulture;
            return ci.Calendar.GetDayOfYear(dt);
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Elapsed time since a given <see cref="DateTime"/>
        /// </summary>
        /// <param name="dt"></param>
        /// <returns>Elapsed time since a given <see cref="DateTime"/></returns>
        public static TimeSpan Elapsed(this DateTime dt)
        {
            var lower = dt.IsBefore(DateTime.Today, true) ? dt : DateTime.Today;
            var upper = lower.Ticks == dt.Ticks ? DateTime.Today : dt;
            return new TimeSpan(upper.Ticks - lower.Ticks);
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Elapsed time between two <see cref="DateTime"/>
        /// </summary>
        /// <param name="dt"></param>
        /// <param name="compare"></param>
        /// <returns>Elapsed time between two <see cref="DateTime"/></returns>
        public static TimeSpan ElapsedAsOf(this DateTime dt, DateTime compare)
        {
            var lower = dt.IsBefore(compare, true) ? dt : compare;
            var upper = lower.Ticks == dt.Ticks ? compare : dt;
            return new TimeSpan(upper.Ticks - lower.Ticks);
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Current age in years from given <see cref="DateTime"/>
        /// </summary>
        /// <param name="dt"></param>
        /// <returns>Current age in years since given <see cref="DateTime"/></returns>
        public static int Age(this DateTime dt)
        {
            if (dt.IsBefore(DateTime.Today, true))
            {
                var iVal = DateTime.Today.Year - dt.Year;
                if (DateTime.Today.Month < dt.Month
                    || (DateTime.Today.Month == dt.Month && DateTime.Today.Day < dt.Day))
                    --iVal;
                return iVal;
            }
            else
            {
                return 0;
            }
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Age in years between two <see cref="DateTime"/>
        /// </summary>
        /// <param name="dt"></param>
        /// <param name="compare"></param>
        /// <returns>Age in years between two <see cref="DateTime"/></returns>
        public static int AgeAsOf(this DateTime dt, DateTime compare)
        {
            if (dt.IsBefore(compare, true))
            {
                var iVal = compare.Year - dt.Year;
                if (compare.Month < dt.Month
                    || (compare.Month == dt.Month && compare.Day < dt.Day))
                    --iVal;
                return iVal;
            }
            else
            {
                return 0;
            }
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Determine if one <see cref="DateTime"/> falls after another
        /// </summary>
        /// <param name="value">Value to test</param>
        /// <param name="query">Value to test against</param>
        /// <param name="inclusive">If <c>true</c> the test is inclusive of value</param>
        /// <returns><c>true</c> if value is after query; otherwise <c>false</c></returns>
        public static bool IsAfter(this DateTime value, DateTime query, bool inclusive)
        {
            if (inclusive)
            {
                return value.Ticks >= query.Ticks;
            }
            else
            {
                return value.Ticks > query.Ticks;
            }
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Determine if one <see cref="DateTime"/> falls before another
        /// </summary>
        /// <param name="value">Value to test</param>
        /// <param name="query">Value to test against</param>
        /// <param name="inclusive">If <c>true</c> the test is inclusive of value</param>
        /// <returns><c>true</c> if value is before query; otherwise <c>false</c></returns>
        public static bool IsBefore(this DateTime value, DateTime query, bool inclusive)
        {
            if (inclusive)
            {
                return value.Ticks <= query.Ticks;
            }
            else
            {
                return value.Ticks < query.Ticks;
            }
        }

        /// <summary>
        /// <see cref="DateTime"/> extension: Determine if one <see cref="DateTime"/> falls between two others
        /// </summary>
        /// <param name="value">Value to test</param>
        /// <param name="lowerbound">Lowerbound value for comparison</param>
        /// <param name="upperbound">Upperbound value for comparison</param>
        /// <param name="inclusive">If <c>true</c> the test is inclusive of value</param>
        /// <returns><c>true</c> if value is within the span of dates defined by lowerbound and upperbound; otherwise <c>false</c></returns>
        public static bool IsBetween(this DateTime value, DateTime lowerbound, DateTime upperbound, bool inclusive)
        {
            var lower = lowerbound.IsBefore(upperbound, inclusive) ? lowerbound : upperbound;
            var upper = upperbound.IsAfter(lowerbound, inclusive) ? upperbound : lowerbound;
            return value.IsAfter(lower, inclusive) && value.IsBefore(upper, inclusive);
        }

        #endregion DateTime Extensions

        #region XElement/XmlNode conversions

        /// <summary>
        /// <see cref="XmlNode"/> extension: Convert <see cref="XmlNode"/> to <see cref="XElement"/>
        /// </summary>
        /// <param name="value">The <see cref="XmlNode"/> to convert</param>
        /// <returns><see cref="XElement"/></returns>
        public static XElement ToXElement(this XmlNode value)
        {
            var xDoc = new XDocument();
            using (var writer = xDoc.CreateWriter()) { value.WriteTo(writer); }
            return xDoc.Root;
        }

        /// <summary>
        /// <see cref="XElement"/> extension: Convert <see cref="XElement"/> to <see cref="XmlNode"/>
        /// </summary>
        /// <param name="value">The <see cref="XElement"/> to convert</param>
        /// <returns><see cref="XmlNode"/></returns>
        public static XmlNode ToXmlNode(this XElement value)
        {
            using (var reader = value.CreateReader())
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.Load(reader);
                return xmlDoc;
            }
        }

        #endregion  XElement/XmlNode conversions

        #region XDocument/XmlDocument conversions

        /// <summary>
        /// <see cref="XmlDocument"/> extension: Convert <see cref="XmlDocument"/> to <see cref="XDocument"/>
        /// </summary>
        /// <param name="value">The <see cref="XmlDocument"/> to convert</param>
        /// <returns><see cref="XDocument"/></returns>
        public static XDocument ToXDocument(this XmlDocument value)
        {
            return value.ToXDocument(LoadOptions.None);
        }

        /// <summary>
        /// <see cref="XmlDocument"/> extension: Convert <see cref="XmlDocument"/> to <see cref="XDocument"/>
        /// </summary>
        /// <param name="value">The <see cref="XmlDocument"/> to convert</param>
        /// <param name="options"><see cref="XDocument"/> <see cref="LoadOptions"/></param>
        /// <returns><see cref="XDocument"/></returns>
        public static XDocument ToXDocument(this XmlDocument value, LoadOptions options)
        {
            using (var reader = new XmlNodeReader(value))
            {
                return XDocument.Load(reader, options);
            }
        }

        /// <summary>
        /// <see cref="XDocument"/> extension: Convert <see cref="XDocument"/> to <see cref="XmlDocument"/>
        /// </summary>
        /// <param name="value">The <see cref="XDocument"/> to convert</param>
        /// <returns><see cref="XmlDocument"/></returns>
        public static XmlDocument ToXmlDocument(this XDocument value)
        {
            using (var reader = value.CreateReader())
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.Load(reader);
                if (value.Declaration != null)
                {
                    var dec = xmlDoc.CreateXmlDeclaration(value.Declaration.Version,
                        value.Declaration.Encoding,
                        value.Declaration.Standalone);
                    xmlDoc.InsertBefore(dec, xmlDoc.FirstChild);
                }
                return xmlDoc;
            }
        }

        #endregion  XDocument/XmlDocument conversions

        #region Stream Extensions

        /// <summary>
        /// Stream Extension: Binary read <see cref="Stream"/> to end
        /// </summary>
        /// <param name="origin">Stream to read</param>
        /// <returns><code>byte[]</code> containing contentof stream</returns>
        public static byte[] BinaryReadToEnd(this Stream origin)
        {
            var buffer = CreateBuffer(0x10000);
            var EOS = false;
            var bytesRead = 0;

            using (var ms = new MemoryStream())
            {
                while (!EOS)
                {
                    bytesRead = origin.Read(buffer, 0, buffer.Length);
                    if (bytesRead > 0) { ms.Write(buffer, 0, bytesRead); } else { EOS = true; }
                }

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Create <code>Stream</code> from <code>string</code>.
        /// </summary>
        /// <param name="origin">The string</param>
        /// <param name="encoder">Encoding to use</param>
        /// <returns><code>Stream</code></returns>
        public static Stream ToStream(this string origin, Encoding encoder)
        {
            return new MemoryStream(encoder.GetBytes(origin));
        }

        #endregion Stream Extensions
    }
}
