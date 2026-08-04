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

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace Owid.Client.Controllers
{
    /// <summary>
    /// Decides whether a request may use the public-key and creator
    /// endpoints. The OWID specification leaves authentication to the
    /// implementor; supply an implementation to require credentials.
    /// </summary>
    public interface IOwidAuthorizer
    {
        /// <summary>
        /// Inspects the request and returns null to allow it, or the action
        /// result to send instead, for example a 401 describing how to
        /// supply a credential. Async so the check can call a database or
        /// another service.
        /// </summary>
        /// <param name="request">The incoming request.</param>
        Task<ActionResult?> AuthorizeAsync(HttpRequest request);
    }
}
