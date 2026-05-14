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

namespace Owid.Client.Model
{
	/// <summary>
	/// A version of <see cref="Owid"/> data.
	/// </summary>
    public enum OwidVersion
	{
		/// <summary>
		/// Represents an empty <see cref="Owid"/>.
		/// </summary>
		Empty = 0,

		/// <summary>
		/// Version 1.
		/// </summary>
		Version1 = 1,

        /// <summary>
        /// Version 2.
        /// </summary>
        Version2 = 2,

        /// <summary>
        /// Version 3.
        /// </summary>
        Version3 = 3,
	}
}
