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

namespace Owid.Client
{
    internal static class Constants
    {
		/// <summary>
		/// The base data for OWIDs. The date and time information is stored
		/// in hours or minutes after this date.
		/// </summary>
		internal static readonly DateTime BaseDate = new DateTime(
			2020, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

		/// <summary>
		/// The largest count of minutes after <see cref="BaseDate"/> that a
		/// <see cref="DateTime"/> can hold, which is 4,197,074,399 and lands
		/// on 9999-12-31 23:59. The four byte count in versions 2 and 3 runs
		/// to 4,294,967,295, which is 15 February 10186, so a count above
		/// this is one the wire format allows and this runtime cannot
		/// represent. Derived from <see cref="DateTime.MaxValue"/> rather
		/// than written as a number so it cannot drift from the runtime.
		/// </summary>
		internal static readonly uint MaximumMinutes = (uint)(
			(DateTime.MaxValue - BaseDate).Ticks / TimeSpan.TicksPerMinute);

		/// <summary>
		/// The length of an OWID signature in bytes. 
		/// </summary>
		internal const int SignatureLength = 64;

		/// <summary>
		/// The greatest number of characters a creator domain can have.
		/// RFC 1035 section 2.3.4 "Size limits" says that "the total length
		/// of a domain name (i.e., label octets and label length octets) is
		/// restricted to 255 octets or less". Those 255 octets are the wire
		/// format, which spends one length octet on every label and one zero
		/// octet on the root, whereas an OWID stores the presentation form,
		/// the text "example.com", where a dot stands in for every label
		/// length octet apart from the first, which has no dot in front of
		/// it, and the root octet has no text form at all, so the same limit
		/// is 253 characters once those two octets are taken away.
		/// </summary>
		internal const int MaximumDomainLength = 253;

		/// <summary>
		/// Used when cryptographic operations are required where there is no
		/// other data to be considered.
		/// </summary>
		internal static readonly Model.Owid[] Empty = new Model.Owid[] { };
	}
}