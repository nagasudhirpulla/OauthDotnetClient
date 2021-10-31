using MediatR;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Core.Entities;

namespace Application.Users.Queries.GetRawUserById
{
    public class GetRawUserByIdQuery : IRequest<ApplicationUser>
    {
        public string Id { get; set; }
        public class GetRawAppUserByIdQueryHandler : IRequestHandler<GetRawUserByIdQuery, ApplicationUser>
        {
            private readonly UserManager<ApplicationUser> _userManager;

            public GetRawAppUserByIdQueryHandler(UserManager<ApplicationUser> userManager)
            {
                _userManager = userManager;
            }

            public async Task<ApplicationUser> Handle(GetRawUserByIdQuery request, CancellationToken cancellationToken)
            {
                if (request.Id == null)
                {
                    return null;
                }
                ApplicationUser user = await _userManager.FindByIdAsync(request.Id);

                return user;
            }
        }
    }
}
