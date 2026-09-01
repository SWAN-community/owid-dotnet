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
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Model;

namespace Owid.Client.Test
{
    /// <summary>
    /// The date a creator stamps on an OWID.
    /// </summary>
    /// <remarks>
    /// A creator that always stamped the moment of signing put a fact into
    /// every identifier that its issuer may not want to state: two
    /// identifiers made for the same person an hour apart are told apart by
    /// their dates alone. An issuer that wants to say only the day says it
    /// here, and these check that what it asked for is what the bytes carry,
    /// since the OWID a caller holds and the OWID it hands on have to agree.
    /// </remarks>
    [TestClass]
    public class CreatorDateTests
    {
        private const string TestDomain = "51degrees.com";

        private static readonly byte[] Payload = { 1, 2, 3 };

        private static readonly DateTime BaseDate =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static Creator NewCreator()
        {
            var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new Creator(TestDomain, crypto);
        }

        /// <summary>
        /// The OWID as it comes back from its own bytes, which is what a
        /// recipient sees and the only date that counts.
        /// </summary>
        private static Model.Owid RoundTrip(Model.Owid owid)
        {
            return TestOwid.Parse(owid.AsByteArray());
        }

        [TestMethod]
        public void DateGiven_IsTheDateCarried()
        {
            var day = new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc);
            var owid = NewCreator().Create(Payload, day);

            Assert.AreEqual(day, owid.Date);
            Assert.AreEqual(day, RoundTrip(owid).Date);
        }

        [TestMethod]
        public void NoDateGiven_StampsTheMomentOfSigning()
        {
            var before = DateTime.UtcNow.AddMinutes(-1);
            var owid = NewCreator().Create(Payload);
            var after = DateTime.UtcNow.AddMinutes(1);

            Assert.IsTrue(
                owid.Date >= before && owid.Date <= after,
                $"stamped '{owid.Date:u}', expected between " +
                $"'{before:u}' and '{after:u}'");
        }

        /// <summary>
        /// Versions 2 and 3 count whole minutes, so seconds cannot survive
        /// the write. The OWID in hand drops them too, rather than claiming
        /// a precision its own bytes do not carry.
        /// </summary>
        [TestMethod]
        public void SecondsGiven_AreDroppedRatherThanClaimed()
        {
            var withSeconds =
                new DateTime(2026, 9, 1, 13, 45, 39, DateTimeKind.Utc);
            var wholeMinute =
                new DateTime(2026, 9, 1, 13, 45, 0, DateTimeKind.Utc);

            var owid = NewCreator().Create(Payload, withSeconds);

            Assert.AreEqual(wholeMinute, owid.Date);
            Assert.AreEqual(wholeMinute, RoundTrip(owid).Date);
        }

        /// <summary>
        /// The same call has to produce the same OWID whichever machine runs
        /// it, so a date with no stated kind is read as UTC rather than as
        /// the server's local time.
        /// </summary>
        [TestMethod]
        public void UnspecifiedKind_IsTakenAsUtc()
        {
            var unspecified = new DateTime(
                2026, 9, 1, 6, 30, 0, DateTimeKind.Unspecified);

            var owid = NewCreator().Create(Payload, unspecified);

            Assert.AreEqual(DateTimeKind.Utc, owid.Date.Kind);
            Assert.AreEqual(
                new DateTime(2026, 9, 1, 6, 30, 0, DateTimeKind.Utc),
                owid.Date);
        }

        [TestMethod]
        public void LocalKind_IsConvertedToUtc()
        {
            var local = new DateTime(
                2026, 9, 1, 6, 30, 0, DateTimeKind.Local);

            var owid = NewCreator().Create(Payload, local);

            Assert.AreEqual(local.ToUniversalTime(), owid.Date);
        }

        [TestMethod]
        public void SignatureCoversTheDateGiven()
        {
            var creator = NewCreator();
            var owid = creator.Create(
                Payload, new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc));

            Assert.AreEqual(
                OwidSignatureStatus.SignatureValid,
                owid.SignatureStatus(creator.Crypto));

            // The same OWID with a different date is a different signed
            // statement, so the signature must no longer stand.
            var moved = creator.Create(
                Payload, new DateTime(2026, 9, 2, 0, 0, 0, DateTimeKind.Utc));
            Assert.AreNotEqual(owid.AsBase64(), moved.AsBase64());
        }

        [TestMethod]
        public void DateBeforeTheBaseDate_IsRefused()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => NewCreator().Create(Payload, BaseDate.AddMinutes(-1)));
        }

        /// <summary>
        /// The wire format's four byte count of minutes runs to February
        /// 10186, well past where a DateTime stops, so no date a caller can
        /// hand over is out of reach on the high side. The last moment the
        /// runtime holds is written as the last whole minute it holds.
        /// </summary>
        [TestMethod]
        public void MaxValue_LandsOnTheLastMinuteTheFormatCounts()
        {
            var owid = NewCreator().Create(Payload, DateTime.MaxValue);

            Assert.AreEqual(
                new DateTime(9999, 12, 31, 23, 59, 0, DateTimeKind.Utc),
                owid.Date);
            Assert.AreEqual(owid.Date, RoundTrip(owid).Date);
        }

        [TestMethod]
        public void LastDateTheFormatCanCount_IsAccepted()
        {
            // 9999-12-31 23:59, the last whole minute a DateTime holds.
            var last = new DateTime(9999, 12, 31, 23, 59, 0, DateTimeKind.Utc);

            var owid = NewCreator().Create(Payload, last);

            Assert.AreEqual(last, owid.Date);
            Assert.AreEqual(last, RoundTrip(owid).Date);
        }

        [TestMethod]
        public void BaseDate_IsAccepted()
        {
            var owid = NewCreator().Create(Payload, BaseDate);

            Assert.AreEqual(BaseDate, owid.Date);
            Assert.AreEqual(BaseDate, RoundTrip(owid).Date);
        }
    }
}
