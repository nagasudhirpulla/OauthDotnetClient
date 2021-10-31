using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Application.Common;
using Application.Users;
using Application.Users.Queries.GetAppUsers;
using Application.Users.Queries.GetUserById;
using Core.Entities;

namespace WebApp.Pages.Users
{
    public class DetailsModel : PageModel
    {

        private readonly ILogger<DetailsModel> _logger;
        private readonly IMediator _mediator;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ICurrentUserService _currentUserService;

        public DetailsModel(ILogger<DetailsModel> logger, IMediator mediator, ICurrentUserService currentUserService, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _mediator = mediator;
            _currentUserService = currentUserService;
            _userManager = userManager;
        }
        public UserDTO CUser { get; set; }

        public async Task<IActionResult> OnGetAsync(string id)
        {
            // check if user is authorized
            string curUsrId = _currentUserService.UserId;
            ApplicationUser curUsr = await _userManager.FindByIdAsync(curUsrId);
            IList<string> usrRoles = await _userManager.GetRolesAsync(curUsr);
            if (id != null && curUsrId != id
                && !usrRoles.Contains(SecurityConstants.AdminRoleString))
            {
                return Unauthorized();
            }

            CUser = await _mediator.Send(new GetUserByIdQuery() { Id = id ?? curUsrId });
            if (CUser == null)
            {
                return NotFound();
            }

            return Page();
        }
    }
}
