using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Owid.Client.Model.Configuration;

namespace Owid.Client.Controllers
{
    [Route("[controller]/api/v1")]
    [Route("[controller]/api/v2")]
    [ApiController]
    public class OwidController : Controller
    {
        private readonly OwidConfiguration _owidConfiguration;

        public OwidController(OwidConfiguration owidConfiguration)
        {
            _owidConfiguration = owidConfiguration;
        }

        /// <summary>
        /// Returns the public key for the OWID creator.
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [HttpGet("public-key")]
        [HttpPost("public-key")]
        public string GetPublicKey()
        {
            return _owidConfiguration.PublicKey;
        }


        /// <summary>
        /// Returns the public key for the OWID creator.
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [HttpGet("creator")]
        [HttpPost("creator")]
        public string GetCreator()
        {
            return _owidConfiguration.Domain;
        }
    }
}
