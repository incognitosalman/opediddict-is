using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Server.Auth.Data
{
    public class ServerDbContext : IdentityDbContext<IdentityUser>
    {
        public ServerDbContext(DbContextOptions<ServerDbContext> options) : base(options)
        {
        }
    }
}
