using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Core.Entities;

namespace Application.Users.Commands.DeleteUser
{
    public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, List<string>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<DeleteUserCommandHandler> _logger;

        public DeleteUserCommandHandler(UserManager<ApplicationUser> userManager, ILogger<DeleteUserCommandHandler> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<List<string>> Handle(DeleteUserCommand request, CancellationToken cancellationToken)
        {
            List<string> errors = new();
            ApplicationUser user = await _userManager.FindByIdAsync(request.Id);
            if (user == null)
            {
                errors.Add($"User not found with id {request.Id}");
            }
            else
            {
                IdentityResult result = await _userManager.DeleteAsync(user);
                if (!result.Succeeded)
                {
                    foreach (IdentityError err in result.Errors)
                    {
                        errors.Add(err.Description);
                    }
                }
            }

            return errors;
        }
    }
}
