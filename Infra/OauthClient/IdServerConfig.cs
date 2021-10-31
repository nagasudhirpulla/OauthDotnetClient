using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infra.OauthClient
{
    public class IdServerConfig
    {
        public string DisplayName { get; set; }
        public string Authority { get; set; }
        public string SignedOutRedirectUri { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public bool RequireHttps { get; set; }
    }
}
