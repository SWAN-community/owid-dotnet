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

namespace Owid.Client.Test
{
    /// <summary>
    /// Tests for the dated key selection rule in <see cref="DatedKeyStore"/>.
    /// </summary>
    [TestClass]
    public class DatedKeyStoreTests
    {
        private static readonly DateTime Epoch =
            new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static uint Minutes(int year, int month, int day)
            => (uint)(new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Utc)
                - Epoch).TotalMinutes;

        // Out of order on purpose, to prove the store sorts.
        private static DatedKeyStore Store()
            => new DatedKeyStore(new List<DatedPublicKey>
            {
                new DatedPublicKey { Created = new DateTime(2026, 3, 8, 0, 0, 0, DateTimeKind.Utc), PublicKey = "k-0308" },
                new DatedPublicKey { Created = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc), PublicKey = "k-0301" },
                new DatedPublicKey { Created = new DateTime(2026, 3, 15, 0, 0, 0, DateTimeKind.Utc), PublicKey = "k-0315" },
            });

        /// <summary>
        /// A date between two keys returns the earlier key.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_BetweenKeys_ReturnsEarlierKey()
        {
            Assert.AreEqual("k-0308", Store().GetPublicKey(Minutes(2026, 3, 10)));
        }

        /// <summary>
        /// No date returns the newest key.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_NoDate_ReturnsNewest()
        {
            Assert.AreEqual("k-0315", Store().GetPublicKey(null));
        }

        /// <summary>
        /// A date exactly equal to a key's Created returns that key, proving
        /// the "on or before" boundary is inclusive.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_ExactlyOnCreated_ReturnsThatKey()
        {
            Assert.AreEqual("k-0308", Store().GetPublicKey(Minutes(2026, 3, 8)));
        }

        /// <summary>
        /// A date after the newest key returns the newest key.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_AfterNewest_ReturnsNewest()
        {
            Assert.AreEqual("k-0315", Store().GetPublicKey(Minutes(2026, 4, 1)));
        }

        /// <summary>
        /// A date before the oldest key returns null.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_BeforeOldest_ReturnsNull()
        {
            Assert.IsNull(Store().GetPublicKey(Minutes(2020, 1, 2)));
        }

        /// <summary>
        /// A value that overflows the date range returns the newest key.
        /// </summary>
        [TestMethod]
        public void GetPublicKey_Overflow_ReturnsNewest()
        {
            Assert.AreEqual("k-0315", Store().GetPublicKey(uint.MaxValue));
        }
    }
}
