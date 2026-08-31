/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Model;

namespace Owid.Client.Test
{
    /// <summary>
    /// Dates the wire format can carry but this runtime cannot.
    /// </summary>
    /// <remarks>
    /// Versions 2 and 3 carry the date as an unsigned 32 bit count of
    /// minutes since 2020-01-01, which runs to 4,294,967,295 and lands on
    /// 15 February 10186. <see cref="DateTime.MaxValue"/> is the last moment
    /// of the year 9999, so the last count the runtime can hold is
    /// 4,197,074,399 and the next cannot be represented. Before the guard,
    /// <c>AddMinutes</c> threw on that count, so a read that promises never
    /// to throw threw on caller data. The same bytes read fine in Java, PHP
    /// and JavaScript, so the finding is the runtime's limit and not a fault
    /// in the data, which is what
    /// <see cref="OwidParseStatus.ImplementationCapacityExceeded"/> means.
    /// Both reading contracts are checked, because each has its own date
    /// arithmetic.
    /// </remarks>
    [TestClass]
    public class DateRangeTests
    {
        private const string TestDomain = "51degrees.com";

        private const string PrivatePEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n" +
            "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n" +
            "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n" +
            "-----END PRIVATE KEY-----";

        /// <summary>
        /// The last count a <see cref="DateTime"/> can hold, which is
        /// 9999-12-31 23:59. Written as a number here, and derived from
        /// <see cref="DateTime.MaxValue"/> in the library, so the two are
        /// checked against each other below.
        /// </summary>
        private const uint LastInside = 4_197_074_399;

        /// <summary>
        /// The first count the runtime cannot hold, one minute into 10000.
        /// </summary>
        private const uint FirstBeyond = LastInside + 1;

        private static readonly DateTime BaseDate =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// A signed version 3 envelope with its date bytes replaced. The date
        /// follows the version byte and the terminated domain, and is four
        /// little endian bytes. The signature no longer matches, which does
        /// not matter, because parsing and verifying are separate questions.
        /// </summary>
        private static byte[] WithMinutes(uint minutes)
        {
            using var crypto = ECDsa.Create();
            crypto.ImportFromPem(PrivatePEM);
            var bytes = new Creator(TestDomain, crypto)
                .Create(new byte[] { 1, 2, 3 })
                .AsByteArray();
            var at = 1 + TestDomain.Length + 1;
            bytes[at] = (byte)minutes;
            bytes[at + 1] = (byte)(minutes >> 8);
            bytes[at + 2] = (byte)(minutes >> 16);
            bytes[at + 3] = (byte)(minutes >> 24);
            return bytes;
        }

        /// <summary>
        /// A version 1 envelope built by hand, because no creator writes
        /// that version any more. Two big endian bytes of hours, then the
        /// payload count, payload and a signature of the right length.
        /// </summary>
        private static byte[] Version1WithHours(int hours)
        {
            return new byte[] { (byte)OwidVersion.Version1 }
                .Concat(System.Text.Encoding.ASCII.GetBytes(TestDomain))
                .Concat(new byte[] { 0 })
                .Concat(new[] { (byte)(hours >> 8), (byte)hours })
                .Concat(new byte[] { 1, 0, 0, 0 })
                .Concat(new byte[] { 7 })
                .Concat(new byte[Constants.SignatureLength])
                .ToArray();
        }

        private static void RefusedOnBothContracts(byte[] bytes)
        {
            Assert.IsFalse(
                Model.Owid.TryParse(bytes, out var whole, out var status));
            Assert.IsNull(whole, "no value is handed back on failure");
            Assert.AreEqual(
                OwidParseStatus.ImplementationCapacityExceeded, status);

            using var stream = new MemoryStream(bytes);
            Assert.IsFalse(
                Model.Owid.TryRead(stream, out var framed, out var framedStatus));
            Assert.IsNull(framed, "no value is handed back on failure");
            Assert.AreEqual(
                OwidParseStatus.ImplementationCapacityExceeded, framedStatus);
        }

        private static DateTime ParsedOnBothContracts(byte[] bytes)
        {
            Assert.IsTrue(
                Model.Owid.TryParse(bytes, out var whole, out var status),
                status.ToString());
            Assert.AreEqual(OwidParseStatus.Parsed, status);

            using var stream = new MemoryStream(bytes);
            Assert.IsTrue(
                Model.Owid.TryRead(stream, out var framed, out var framedStatus),
                framedStatus.ToString());
            Assert.AreEqual(OwidParseStatus.Parsed, framedStatus);
            Assert.AreEqual(whole!.Date, framed!.Date);
            return whole.Date;
        }

        /// <summary>
        /// The largest count the wire can carry.
        /// </summary>
        [TestMethod]
        public void MaximumCount_IsCapacityExceeded()
        {
            RefusedOnBothContracts(WithMinutes(uint.MaxValue));
        }

        /// <summary>
        /// The first count past the runtime, one minute into the year 10000.
        /// </summary>
        [TestMethod]
        public void FirstCountBeyondTheRuntime_IsCapacityExceeded()
        {
            RefusedOnBothContracts(WithMinutes(FirstBeyond));
        }

        /// <summary>
        /// The last count inside the runtime parses, and to the right minute.
        /// </summary>
        [TestMethod]
        public void LastCountInsideTheRuntime_Parses()
        {
            var date = ParsedOnBothContracts(WithMinutes(LastInside));
            Assert.AreEqual(
                new DateTime(9999, 12, 31, 23, 59, 0, DateTimeKind.Utc),
                date);
        }

        /// <summary>
        /// Pins the boundary to the runtime rather than to a number someone
        /// worked out once. The library derives it and this test states it,
        /// and the arithmetic the guard prevents is shown to throw.
        /// </summary>
        [TestMethod]
        public void TheBoundaryIsTheLastWholeMinuteBeforeMaxValue()
        {
            Assert.AreEqual(LastInside, Constants.MaximumMinutes);
            Assert.IsTrue(BaseDate.AddMinutes(LastInside) <= DateTime.MaxValue);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => BaseDate.AddMinutes(FirstBeyond));
        }

        /// <summary>
        /// Version 1 counts hours in two bytes, so its largest count is
        /// 65,535 hours, which is 23 June 2027 and under eight years from
        /// the base date. The arithmetic cannot leave the runtime's range,
        /// so the reader has no guard for it and this shows none is needed.
        /// </summary>
        [TestMethod]
        public void Version1MaximumHours_Parses()
        {
            var date = ParsedOnBothContracts(Version1WithHours(0xFFFF));
            Assert.AreEqual(
                new DateTime(2027, 6, 23, 15, 0, 0, DateTimeKind.Utc),
                date);
        }
    }
}
