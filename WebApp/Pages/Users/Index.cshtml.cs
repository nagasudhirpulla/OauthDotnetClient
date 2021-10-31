using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Application.Users;
using Application.Users.Queries.GetAppUsers;

namespace WebApp.Pages.Users
{
    [Authorize(Roles = SecurityConstants.AdminRoleString)]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly IMediator _mediator;
        public IList<UserDTO> Users { get; set; }

        public IndexModel(ILogger<IndexModel> logger, IMediator mediator)
        {
            _logger = logger;
            _mediator = mediator;
        }
        
        public async Task OnGetAsync()
        {
            Users = (await _mediator.Send(new GetAppUsersQuery())).Users;
        }
    }
}
