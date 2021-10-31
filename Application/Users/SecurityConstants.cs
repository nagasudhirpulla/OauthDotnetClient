using System.Collections.Generic;
using System.Linq;

namespace Application.Users
{
    public static class SecurityConstants
    {
        public const string GuestRoleString = "GuestUser";
        public const string AdminRoleString = "Administrator";
        public const string EmployeeRoleString = "Employee";
        public static List<string> GetRoles()
        {
            return typeof(SecurityConstants).GetFields().Select(x => x.GetValue(null).ToString()).ToList();
        }
    }
}
