using AutoMapper;
using MediatR;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Application.Users.Queries.GetAppUsers;
using Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace Application.Users.Queries.GetUserById
{
    public class GetUserByIdQuery : IRequest<UserDTO>
    {
        public string Id { get; set; }
        public class GetUserByIdQueryHandler : IRequestHandler<GetUserByIdQuery, UserDTO>
        {
            private readonly UserManager<ApplicationUser> _userManager;
            private readonly IMapper _mapper;

            public GetUserByIdQueryHandler(UserManager<ApplicationUser> userManager, IMapper mapper)
            {
                _userManager = userManager;
                _mapper = mapper;
            }

            public async Task<UserDTO> Handle(GetUserByIdQuery request, CancellationToken cancellationToken)
            {
                if (request.Id == null)
                {
                    return null;
                }

                ApplicationUser user = await _userManager.Users.FirstOrDefaultAsync(u => u.Id == request.Id, cancellationToken: cancellationToken);
                if (user == null)
                {
                    return null;
                }

                IList<string> existingUserRoles = (await _userManager.GetRolesAsync(user));
                string userRole = SecurityConstants.GuestRoleString;
                if (existingUserRoles.Count > 0)
                {
                    userRole = existingUserRoles.ElementAt(0);
                }
                UserDTO vm = _mapper.Map<UserDTO>(user);
                vm.UserRole = userRole;
                return vm;
            }
        }
    }
}
