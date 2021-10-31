using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Application.Users;
using Application.Users.Commands.DeleteUser;
using Application.Users.Queries.GetAppUsers;
using Application.Users.Queries.GetUserById;
using WebApp.Extensions;

namespace WebApp.Pages.Users
{
    [Authorize(Roles = SecurityConstants.AdminRoleString)]
    public class DeleteModel : PageModel
    {
        private readonly ILogger<DeleteModel> _logger;
        private readonly IMediator _mediator;
        private readonly IMapper _mapper;

        public DeleteModel(ILogger<DeleteModel> logger, IMediator mediator, IMapper mapper)
        {
            _logger = logger;
            _mediator = mediator;
            _mapper = mapper;
        }

        [BindProperty]
        public UserDTO DUser { get; set; }

        public async Task<IActionResult> OnGetAsync(string id)
        {
            DUser = await _mediator.Send(new GetUserByIdQuery() { Id = id });

            if (DUser == null)
            {
                return NotFound();
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            List<string> errs = await _mediator.Send(new DeleteUserCommand() { Id = DUser.UserId });

            if (errs.Count == 0)
            {
                _logger.LogInformation("User deleted successfully");
                return RedirectToPage($"./{nameof(Index)}").WithSuccess("User deletion done");
            }

            foreach (var error in errs)
            {
                ModelState.AddModelError(string.Empty, error);
            }

            return Page();
        }
    }
}
