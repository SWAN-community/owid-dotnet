namespace Owid.Client.Model.Configuration
{ 
    public class OwidConfiguration
    {
        /// <summary>
        /// Domain associated with the OWID creator. Contains well known end
        /// points to provide public keys and other information needed to 
        /// conform to the OWID specification.
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        /// The PEM format private key for the OWID creator.
        /// </summary>
        public string PrivateKey { get; set; }

        /// <summary>
        /// The PEM format public key for the OWID creator.
        /// </summary>
        public string PublicKey { get; set; }
    }
}
