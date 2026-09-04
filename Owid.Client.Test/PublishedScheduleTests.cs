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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Owid.Client.Test
{
    /// <summary>
    /// Verifies a genuine identifier against the key schedule its creator
    /// published, using this library exactly as an integrator would.
    /// </summary>
    /// <remarks>
    /// The fixture is real. The identifier in
    /// Data/51did-published-identifier.json was created by the 51Degrees
    /// cloud on 4 September 2026, and Data/51did-published-keys.json is the
    /// thirty week schedule of public keys the same creator published. Both
    /// are public and neither holds a secret, because a public key and a
    /// signed identifier are what a verifier is meant to be given.
    ///
    /// This is the test that would have caught the defect fixed alongside it.
    /// The unit tests around <see cref="DatedKeyStore"/> all passed whilst
    /// the library rejected every genuine identifier of that week, because
    /// they were written around the same wrong idea as the code, being that
    /// the moment a key was generated says when it signs. Only a real
    /// schedule with a real identifier settles that, so keep this test
    /// pointed at published artefacts rather than at anything the tests
    /// build for themselves.
    /// </remarks>
    [TestClass]
    public class PublishedScheduleTests
    {
        /// <summary>
        /// The OWID date encoding counts minutes from this moment.
        /// </summary>
        private static readonly DateTime Epoch =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// One entry of the published schedule. StartsAt is when the key
        /// comes into force and Created is when the key material was
        /// generated, which are different questions and, for a creator that
        /// writes several weeks in one run, different answers.
        /// </summary>
        private class PublishedKey
        {
            [JsonPropertyName("startsAt")]
            public DateTime StartsAt { get; set; }

            [JsonPropertyName("created")]
            public DateTime Created { get; set; }

            [JsonPropertyName("publicKey")]
            public string PublicKey { get; set; } = string.Empty;
        }

        private class PublishedIdentifier
        {
            [JsonPropertyName("identifier")]
            public string Identifier { get; set; } = string.Empty;

            [JsonPropertyName("domain")]
            public string Domain { get; set; } = string.Empty;
        }

        private static string Read(string name)
        {
            var stream = Assembly
                .GetExecutingAssembly()
                .GetManifestResourceStream(name);
            Assert.IsNotNull(stream, $"test data {name} is not embedded");
            using (var reader = new StreamReader(stream!))
            {
                return reader.ReadToEnd();
            }
        }

        private static List<PublishedKey> Schedule()
        {
            var keys = JsonSerializer.Deserialize<List<PublishedKey>>(
                Read("51did-published-keys.json"));
            Assert.IsNotNull(keys);
            return keys!;
        }

        private static PublishedIdentifier Identifier()
        {
            var identifier = JsonSerializer.Deserialize<PublishedIdentifier>(
                Read("51did-published-identifier.json"));
            Assert.IsNotNull(identifier);
            return identifier!;
        }

        private static uint DateMinutes(Model.Owid owid)
            => (uint)(owid.Date - Epoch).TotalMinutes;

        /// <summary>
        /// The published schedule really does carry a batch of keys that
        /// share one moment of generation, so the rest of these tests are
        /// measuring the shape that occurs in production rather than one
        /// invented here. Written as its own test so that a refreshed
        /// fixture without a batch in it fails loudly instead of quietly
        /// making the tests below prove nothing.
        /// </summary>
        [TestMethod]
        public void PublishedSchedule_CarriesABatchWrittenInOneRun()
        {
            var schedule = Schedule();
            Assert.AreEqual(30, schedule.Count);

            var largestBatch = schedule
                .GroupBy(k => k.Created)
                .OrderByDescending(g => g.Count())
                .First();
            Assert.AreEqual(
                13,
                largestBatch.Count(),
                "thirteen keys were written in one run on 1 September 2026");
            Assert.AreEqual(
                12,
                (largestBatch.Max(k => k.StartsAt)
                    - largestBatch.Min(k => k.StartsAt)).Days / 7,
                "and their periods run forward a week at a time");
        }

        /// <summary>
        /// The genuine identifier verifies under the key the store selects
        /// for its own date. This is the whole point of the fixture.
        /// </summary>
        [TestMethod]
        public void GenuineIdentifier_VerifiesUnderTheKeyTheStoreSelects()
        {
            var published = Identifier();
            Assert.IsTrue(
                Model.Owid.TryParse(
                    published.Identifier, out var owid, out var status),
                $"the fixture identifier did not parse: {status}");
            Assert.AreEqual(published.Domain, owid!.Domain);
            Assert.AreEqual(
                new DateTime(2026, 9, 4, 0, 0, 0, DateTimeKind.Utc),
                owid.Date);

            var store = new DatedKeyStore(Schedule().Select(
                k => new DatedPublicKey
                {
                    StartsAt = k.StartsAt,
                    PublicKey = k.PublicKey,
                }));
            var pem = store.GetPublicKey(DateMinutes(owid));
            Assert.IsNotNull(pem, "no key was selected for the identifier");

            // Asserted before the identity of the key, because this is the
            // answer that matters. SignatureInvalid here means the library
            // is calling a genuine identifier a forgery.
            Assert.AreEqual(
                OwidSignatureStatus.SignatureValid,
                owid.SignatureStatus(pem!),
                "a genuine identifier did not verify under the selected key");
            Assert.AreEqual(
                new DateTime(2026, 8, 31, 0, 0, 0, DateTimeKind.Utc),
                Schedule().Single(k => k.PublicKey == pem).StartsAt,
                "the key in force on 4 September starts on 31 August");
        }

        /// <summary>
        /// The measurement that named the defect, kept so the wrong rule
        /// cannot come back unnoticed. Selecting on the moment of generation
        /// picks the key that starts on 7 September, a period that had not
        /// begun when the identifier was signed, and the answer is
        /// SignatureInvalid. Invalid is the one status that means forgery, so
        /// the library was calling genuine identifiers forged.
        /// </summary>
        [TestMethod]
        public void SelectingOnTheMomentOfGeneration_CallsAGenuineIdForged()
        {
            var schedule = Schedule();
            Assert.IsTrue(
                Model.Owid.TryParse(
                    Identifier().Identifier, out var owid, out _));

            var byCreated = schedule
                .Where(k => k.Created <= owid!.Date)
                .OrderByDescending(k => k.Created)
                .First();
            Assert.AreEqual(
                new DateTime(2026, 9, 7, 0, 0, 0, DateTimeKind.Utc),
                byCreated.StartsAt,
                "the old rule chose the week starting 7 September");
            Assert.AreEqual(
                OwidSignatureStatus.SignatureInvalid,
                owid!.SignatureStatus(byCreated.PublicKey),
                "which reads as forgery for a genuine identifier");
        }

        /// <summary>
        /// Every week of the published schedule selects its own key, so the
        /// rule holds across the whole thirty weeks and not only on the day
        /// the fault was found. Each week is asked at its first moment, in
        /// the middle, and a minute before the next one starts.
        /// </summary>
        [TestMethod]
        public void EveryWeekOfThePublishedSchedule_SelectsItsOwnKey()
        {
            var schedule = Schedule();
            var store = new DatedKeyStore(schedule.Select(
                k => new DatedPublicKey
                {
                    StartsAt = k.StartsAt,
                    PublicKey = k.PublicKey,
                }));
            foreach (var key in schedule)
            {
                foreach (var moment in new[]
                {
                    key.StartsAt,
                    key.StartsAt.AddDays(3),
                    key.StartsAt.AddDays(7).AddMinutes(-1),
                })
                {
                    var minutes = (uint)(moment - Epoch).TotalMinutes;
                    Assert.AreEqual(
                        key.PublicKey,
                        store.GetPublicKey(minutes),
                        $"{moment:yyyy-MM-dd HH:mm} did not select the "
                            + "key of the week starting "
                            + $"{key.StartsAt:yyyy-MM-dd}");
                }
            }
        }
    }
}
