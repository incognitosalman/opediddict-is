using Microsoft.AspNetCore.Mvc;

namespace Server.Auth.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
