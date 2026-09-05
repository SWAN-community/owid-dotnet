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
using System.Linq;

namespace Owid.Client.Test
{
    /// <summary>
    /// Tests for the key selection rule in <see cref="DatedKeyStore"/>, which
    /// is the key in force at the identifier's date, being the latest key
    /// whose <see cref="DatedPublicKey.StartsAt"/> is at or before it.
    /// </summary>
    /// <remarks>
    /// These tests used to be written around the moment each key was
    /// generated, and that is what held the wrong rule in place. Generation
    /// order matches schedule order only whilst keys are generated one at a
    /// time, and a creator that writes a batch of future weeks in one run
    /// breaks the match. GetPublicKey_BatchSharingOneMomentOfGeneration
    /// below is that shape.
    /// </remarks>
    [TestClass]
    public class DatedKeyStoreTests
    {
        private static readonly DateTime Epoch =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static uint Minutes(int year, int month, int day)
            => (uint)(new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Utc)
                - Epoch).TotalMinutes;

        private static DateTime Utc(int year, int month, int day)
            => new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Utc);

        // Out of order on purpose, to prove the store sorts.
        private static DatedKeyStore Store()
            => new DatedKeyStore(new List<DatedPublicKey>
            {
                new DatedPublicKey
                {
                    StartsAt = Utc(2026, 3, 8),
                    PublicKey = "k-0308",
                },
                new DatedPublicKey
                {
                    StartsAt = Utc(2026, 3, 1),
                    PublicKey = "k-0301",
                },
                new DatedPublicKey
                {
                    StartsAt = Utc(2026, 3, 15),
                    PublicKey = "k-0315",
                },
            });

        /// <summary>
        /// A date between two starts returns the key whose period covers it.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_BetweenStarts_ReturnsKeyInForce()
        {
            Assert.AreEqual(
                "k-0308", Store().GetPublicKey(Minutes(2026, 3, 10)));
        }

        /// <summary>
        /// A date exactly on a key's start returns that key, so the boundary
        /// belongs to the period that begins rather than the one that ends.
        /// A creator signs with the new key from the first moment of the new
        /// period, so an identifier stamped at that moment must verify.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_ExactlyOnStart_ReturnsThatKey()
        {
            Assert.AreEqual(
                "k-0308", Store().GetPublicKey(Minutes(2026, 3, 8)));
        }

        /// <summary>
        /// One minute before a start still returns the previous key.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_MinuteBeforeStart_ReturnsPreviousKey()
        {
            var minuteBefore = Minutes(2026, 3, 8) - 1;
            Assert.AreEqual("k-0301", Store().GetPublicKey(minuteBefore));
        }

        /// <summary>
        /// A date after the last start returns the last key, because a key
        /// holds until the next one starts and the last has no next.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_AfterLastStart_ReturnsLastKey()
        {
            Assert.AreEqual(
                "k-0315", Store().GetPublicKey(Minutes(2026, 4, 1)));
        }

        /// <summary>
        /// A date before the first start returns null, because no key was
        /// signing then and no answer is better than the wrong key.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_BeforeFirstStart_ReturnsNull()
        {
            Assert.IsNull(Store().GetPublicKey(Minutes(2020, 1, 2)));
        }

        /// <summary>
        /// A value that overflows the date range is after every key, so the
        /// latest key answers.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_Overflow_ReturnsLatestKey()
        {
            Assert.AreEqual("k-0315", Store().GetPublicKey(uint.MaxValue));
        }

        /// <summary>
        /// No date returns the key in force now, which for this schedule of
        /// past starts is the latest of them.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_NoDate_ReturnsKeyInForceNow()
        {
            Assert.AreEqual("k-0315", Store().GetPublicKey(null));
        }

        /// <summary>
        /// No date never returns a key whose period has not begun. A creator
        /// publishes its schedule ahead of time, so the last entry is usually
        /// a future key, and serving that as the current key would fail every
        /// check of an identifier signed today.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_NoDate_IgnoresKeysNotYetStarted()
        {
            var now = DateTime.UtcNow;
            var store = new DatedKeyStore(new[]
            {
                new DatedPublicKey
                {
                    StartsAt = now.AddDays(-7),
                    PublicKey = "in-force",
                },
                new DatedPublicKey
                {
                    StartsAt = now.AddDays(7),
                    PublicKey = "not-started",
                },
                new DatedPublicKey
                {
                    StartsAt = now.AddDays(14),
                    PublicKey = "not-started-either",
                },
            });
            Assert.AreEqual("in-force", store.GetPublicKey(null));
        }

        /// <summary>
        /// An empty store answers null rather than throwing, for both the
        /// dated and the undated question.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_NoKeys_ReturnsNull()
        {
            var store = new DatedKeyStore(Array.Empty<DatedPublicKey>());
            Assert.IsNull(store.GetPublicKey(null));
            Assert.IsNull(store.GetPublicKey(Minutes(2026, 3, 10)));
        }

        /// <summary>
        /// A key as it is published, carrying both the start of its period
        /// and the moment the key material was generated. Only the test uses
        /// the second of those, to show what selecting on it would choose.
        /// </summary>
        private class ScheduledKey
        {
            public DateTime StartsAt { get; set; }
            public DateTime Created { get; set; }
            public string PublicKey { get; set; } = string.Empty;
        }

        /// <summary>
        /// Thirteen keys written in one run share a single moment of
        /// generation whilst their periods run forward a week at a time.
        /// This is the shape that broke the old rule, and it is taken from
        /// what a 51Degrees creator published on 1 September 2026. The store
        /// must select the key whose period covers the date, and the test
        /// also shows that selecting on the moment of generation picks a key
        /// from a period that has not started.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_BatchSharingOneMomentOfGeneration()
        {
            // One key a week generated on the day it starts, then a batch of
            // thirteen weeks written in a single run on 1 September.
            var batchWrittenAt = new DateTime(
                2026, 9, 1, 10, 54, 0, DateTimeKind.Utc);
            var schedule = new List<ScheduledKey>();
            for (var week = 0; week < 4; week++)
            {
                var startsAt = Utc(2026, 8, 10).AddDays(7 * week);
                schedule.Add(new ScheduledKey
                {
                    StartsAt = startsAt,
                    Created = startsAt.AddHours(4),
                    PublicKey = $"k-{startsAt:MMdd}",
                });
            }
            for (var week = 0; week < 13; week++)
            {
                var startsAt = Utc(2026, 9, 7).AddDays(7 * week);
                schedule.Add(new ScheduledKey
                {
                    StartsAt = startsAt,
                    Created = batchWrittenAt,
                    PublicKey = $"k-{startsAt:MMdd}",
                });
            }
            Assert.AreEqual(
                13,
                schedule.Count(k => k.Created == batchWrittenAt),
                "the batch is the point of this test");

            var store = new DatedKeyStore(schedule.Select(
                k => new DatedPublicKey
                {
                    StartsAt = k.StartsAt,
                    PublicKey = k.PublicKey,
                }));

            // 4 September sits inside the week that started on 31 August.
            Assert.AreEqual(
                "k-0831",
                store.GetPublicKey(Minutes(2026, 9, 4)),
                "the key in force on 4 September starts on 31 August");

            // What the moment of generation would choose instead. The batch
            // is newer than every key that had actually started, so it wins
            // on that measure and hands back a period that has not begun.
            var byCreated = schedule
                .Where(k => k.Created <= Utc(2026, 9, 4))
                .OrderByDescending(k => k.Created)
                .First();
            Assert.AreNotEqual(
                "k-0831",
                byCreated.PublicKey,
                "selecting on the moment of generation must be shown wrong");
            Assert.IsTrue(
                byCreated.StartsAt > Utc(2026, 9, 4),
                "and wrong by choosing a period that has not started");

            // Every week of the schedule selects its own key, including each
            // week of the batch.
            foreach (var key in schedule)
            {
                var midWeek = key.StartsAt.AddDays(3);
                var minutes = (uint)(midWeek - Epoch).TotalMinutes;
                Assert.AreEqual(
                    key.PublicKey,
                    store.GetPublicKey(minutes),
                    $"the week of {key.StartsAt:yyyy-MM-dd} did not select "
                        + "its own key");
            }
        }
    }
}
