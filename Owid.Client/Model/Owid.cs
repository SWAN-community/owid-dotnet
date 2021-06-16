﻿/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
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

using Microsoft.AspNetCore.WebUtilities;
using System;
using System.IO;

namespace Owid.Client.Model
{
    /// <summary>
    /// OWID structure which can be used as a node in a tree.
    /// </summary>
    public class Owid
    {
		/// <summary>
		// The byte version of the OWID. Version 1 only.
		/// </summary>
		public OwidVersion Version { get; set; } = OwidVersion.Version2;

		/// <summary>
		/// Domain associated with the creator.
		/// </summary>
		public string Domain { get; set; }

		/// <summary>
		/// The date and time to the nearest minute in UTC of the creation.
		/// </summary>
		public DateTime Date { get; set; } = DateTime.UtcNow;

		/// <summary>
		/// Array of bytes that form the identifier.
		/// </summary>
		public byte[] Payload { get; set; }

		/// <summary>
		/// Signature for this OWID and it's ancestor from the creator.
		/// </summary>
		public byte[] Signature { get; set; }

		public Owid() { }

		public Owid(string value)
			: this (Base64UrlTextEncoder.Decode(value))
        {
        }

		public Owid(byte[] buffer)
        {
			using (var stream = new MemoryStream(buffer))
			using (var reader = new BinaryReader(stream))
            {
				Version = (OwidVersion)reader.ReadByte();
				switch (Version) {
					case OwidVersion.Empty:
						break;
					case OwidVersion.Version1:
					case OwidVersion.Version2:
						this.FromBuffer(reader);
						break;
				}
			}
        }

        public override string ToString()
        {
            return this.AsBase64();
        }
    }
}