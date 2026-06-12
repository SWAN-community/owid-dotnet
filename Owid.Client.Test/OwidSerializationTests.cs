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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Owid.Client.Model;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Owid.Client.Test
{
    /// <summary>
    /// Tests for version handling and date precision when serializing and
    /// deserializing <see cref="Model.Owid"/> instances.
    /// </summary>
    [TestClass]
    public class OwidSerializationTests
    {
        private const string TestText = "Hello World";
        private const string TestDomain = "test.com";

        /// <summary>
        /// The base date for OWID date fields. Dates are stored as hours
        /// after this date for version 1 and minutes after this date for
        /// versions 2 and 3.
        /// </summary>
        private static readonly DateTime BaseDate = new DateTime(
            2020, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private string? PublicPEM;
        private string? PrivatePEM;

        /// <summary>
        /// Initialize the test.
        /// </summary>
        [TestInitialize]
        public void TestInitialize()
        {
            using (var crypto = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var pubKeyBytes = crypto.ExportSubjectPublicKeyInfo();
                var privKeyBytes = crypto.ExportPkcs8PrivateKey();
                PublicPEM = new String(PemEncoding.Write(
                    "PUBLIC KEY", pubKeyBytes));
                PrivatePEM = new String(PemEncoding.Write(
                    "PRIVATE KEY", privKeyBytes));
            }
        }

        /// <summary>
        /// Test that a version 3 OWID date survives serialization to the
        /// minute.
        /// </summary>
        [TestMethod]
        public void TestDatePrecisionVersion3()
        {
            var owid = CreateOwid(OwidVersion.Version3);
            var copy = new Model.Owid(owid.AsByteArray());
            Assert.AreEqual(OwidTests.FloorToMinute(owid.Date), copy.Date);
            Assert.AreEqual(0, copy.Date.Second);
        }

        /// <summary>
        /// Test that a version 2 OWID date survives serialization to the
        /// minute.
        /// </summary>
        [TestMethod]
        public void TestDatePrecisionVersion2()
        {
            var owid = CreateOwid(OwidVersion.Version2);
            var copy = new Model.Owid(owid.AsByteArray());
            Assert.AreEqual(OwidTests.FloorToMinute(owid.Date), copy.Date);
            Assert.AreEqual(0, copy.Date.Second);
        }

        /// <summary>
        /// Test that a version 1 OWID date survives serialization only to
        /// the hour. Version 1 stores the date as a two byte count of hours
        /// after the base date so the precision is coarser than versions 2
        /// and 3.
        /// </summary>
        [TestMethod]
        public void TestDatePrecisionVersion1()
        {
            var owid = CreateOwid(OwidVersion.Version1);
            var copy = new Model.Owid(owid.AsByteArray());
            var expected = BaseDate.AddHours(
                (ushort)(owid.Date - BaseDate).TotalHours);
            Assert.AreEqual(expected, copy.Date);
            Assert.AreEqual(0, copy.Date.Minute);
            Assert.AreEqual(0, copy.Date.Second);
        }

        /// <summary>
        /// Test that a buffer written with the version 1 date layout is read
        /// back with the expected date. Version 1 stores the hours after the
        /// base date as two big endian bytes.
        /// </summary>
        [TestMethod]
        public void TestVersion1DateReadFromBuffer()
        {
            var date = new DateTime(2021, 2, 3, 4, 0, 0, DateTimeKind.Utc);
            var hours = (ushort)(date - BaseDate).TotalHours;
            var owid = new Model.Owid(BuildBuffer(
                OwidVersion.Version1,
                writer =>
                {
                    writer.Write((byte)(hours >> 8));
                    writer.Write((byte)(hours & 0xFF));
                }));
            Assert.AreEqual(OwidVersion.Version1, owid.Version);
            Assert.AreEqual(date, owid.Date);
        }

        /// <summary>
        /// Test that a buffer written with the version 2 date layout is read
        /// back with the expected date. Versions 2 and 3 store the minutes
        /// after the base date as a four byte little endian integer.
        /// </summary>
        [TestMethod]
        public void TestVersion2DateReadFromBuffer()
        {
            var date = new DateTime(2021, 2, 3, 4, 5, 0, DateTimeKind.Utc);
            var minutes = (uint)(date - BaseDate).TotalMinutes;
            var owid = new Model.Owid(BuildBuffer(
                OwidVersion.Version2,
                writer => writer.Write(minutes)));
            Assert.AreEqual(OwidVersion.Version2, owid.Version);
            Assert.AreEqual(date, owid.Date);
        }

        /// <summary>
        /// Test that a version 1 OWID round trips through a byte array and
        /// still verifies.
        /// </summary>
        [TestMethod]
        public async Task TestVersion1Roundtrip()
        {
            await TestVersionRoundtrip(OwidVersion.Version1);
        }

        /// <summary>
        /// Test that a version 2 OWID round trips through a byte array and
        /// still verifies.
        /// </summary>
        [TestMethod]
        public async Task TestVersion2Roundtrip()
        {
            await TestVersionRoundtrip(OwidVersion.Version2);
        }

        /// <summary>
        /// Test that an unsupported version byte throws a clean exception
        /// when parsing.
        /// </summary>
        [TestMethod]
        public void TestUnsupportedVersionThrows()
        {
            var bytes = CreateOwid(OwidVersion.Version3).AsByteArray();
            bytes[0] = 9;
            Assert.ThrowsExactly<Exception>(() => new Model.Owid(bytes));
        }

        /// <summary>
        /// Test that an empty OWID marker written with
        /// <see cref="Extensions.EmptyToBuffer(BinaryWriter)"/> reads back as
        /// an empty OWID with default field values.
        /// </summary>
        [TestMethod]
        public void TestEmptyOwidMarkerRoundtrip()
        {
            byte[] bytes;
            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    Extensions.EmptyToBuffer(writer);
                }
                bytes = stream.ToArray();
            }

            // The empty marker is a single zero byte.
            Assert.AreEqual(1, bytes.Length);
            Assert.AreEqual(0, bytes[0]);

            var owid = new Model.Owid(bytes);
            Assert.AreEqual(OwidVersion.Empty, owid.Version);
            Assert.AreEqual(string.Empty, owid.Domain);
            Assert.AreEqual(0, owid.Payload.Length);
            Assert.AreEqual(0, owid.Signature.Length);
        }

        private async Task TestVersionRoundtrip(OwidVersion version)
        {
            var owid = CreateOwid(version);
            var copy = new Model.Owid(owid.AsByteArray());

            Assert.AreEqual(version, copy.Version);
            Assert.AreEqual(owid.Domain, copy.Domain);
            CollectionAssert.AreEqual(owid.Payload, copy.Payload);
            CollectionAssert.AreEqual(owid.Signature, copy.Signature);

            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PublicPEM);
                Assert.IsTrue(await copy.VerifyAsync(crypto));
            }
        }

        private Model.Owid CreateOwid(OwidVersion version)
        {
            var owid = new Model.Owid();
            owid.Version = version;
            using (var crypto = ECDsa.Create())
            {
                crypto.ImportFromPem(PrivatePEM);
                var creator = new Creator(TestDomain, crypto);
                owid.Payload = Encoding.ASCII.GetBytes(TestText);
                creator.Sign(owid);
            }
            return owid;
        }

        /// <summary>
        /// Builds a serialized OWID buffer with the given version byte and
        /// date written by the provided action. The signature is a dummy 64
        /// byte array as these fixtures only exercise parsing.
        /// </summary>
        private static byte[] BuildBuffer(
            OwidVersion version,
            Action<BinaryWriter> writeDate)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    writer.Write((byte)version);
                    writer.Write(Encoding.ASCII.GetBytes(TestDomain));
                    writer.Write((byte)0);
                    writeDate(writer);
                    var payload = Encoding.ASCII.GetBytes(TestText);
                    writer.Write((uint)payload.Length);
                    writer.Write(payload);
                    writer.Write(new byte[64]);
                }
                return stream.ToArray();
            }
        }
    }
}
