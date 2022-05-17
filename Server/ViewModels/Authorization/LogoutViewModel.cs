using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Server.Auth.ViewModels.Authorization;

public class LogoutViewModel
{
    [BindNever]
    public string RequestId { get; set; }
}
