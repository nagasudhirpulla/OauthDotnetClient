using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace WebApp.Extensions
{
    public static class StatusBaloonExtensions
    {
        // https://www.trycatchfail.com/2018/01/22/easily-add-bootstrap-alerts-to-your-viewresults-with-asp-net-core/
        public static IActionResult WithSuccess(this IActionResult result, string body)
        {
            return Alert(result, "success", body);
        }

        public static IActionResult WithInfo(this IActionResult result, string body)
        {
            return Alert(result, "info", body);
        }

        public static IActionResult WithWarning(this IActionResult result, string body)
        {
            return Alert(result, "warning", body);
        }

        public static IActionResult WithDanger(this IActionResult result, string body)
        {
            return Alert(result, "danger", body);
        }

        private static IActionResult Alert(IActionResult result, string type, string body)
        {
            return new AlertDecoratorResult(result, type, body);
        }
    }

    public class AlertDecoratorResult : IActionResult
    {
        public IActionResult Result { get; }
        public string Type { get; }
        public string Title { get; }
        public string Body { get; }

        public AlertDecoratorResult(IActionResult result, string type, string body)
        {
            Result = result;
            Type = type;
            Body = body;
        }

        public async Task ExecuteResultAsync(ActionContext context)
        {
            //NOTE: Be sure you add a using statement for Microsoft.Extensions.DependencyInjection, otherwise
            //      this overload of GetService won't be available!
            var factory = context.HttpContext.RequestServices.GetService<ITempDataDictionaryFactory>();

            var tempData = factory.GetTempData(context.HttpContext);
            tempData["_alert.type"] = Type;
            tempData["_alert.body"] = Body;

            await Result.ExecuteResultAsync(context);
        }
    }
}