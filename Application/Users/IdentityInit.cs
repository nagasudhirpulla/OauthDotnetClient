using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Text;

namespace Application.Users
{
    public class IdentityInit
    {
        public string AdminEmail { get; set; }
        public string AdminPassword { get; set; }
        public string AdminUserName { get; set; }
        public string GuestEmail { get; set; }
        public string GuestPassword { get; set; }
        public string GuestUserName { get; set; }
    }
}
