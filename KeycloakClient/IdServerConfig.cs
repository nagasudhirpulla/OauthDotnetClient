using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeycloakClient
{
    public class IdServerConfig
    {
        public string Authority { get; set; }
        public string SignedOutRedirectUri { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}
