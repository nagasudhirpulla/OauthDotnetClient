using Core.Sms;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Infra.Services.Sms
{
    public class SmsSender : ISmsSender
    {
        private readonly SmsConfiguration _smsConfig;
        public SmsSender(SmsConfiguration smsConfig)
        {
            _smsConfig = smsConfig;
        }

        public Task SendSmsAsync(string number, string message)
        {
            // https://www.smscountry.com/Developers.aspx?code=httpjava&sft=1
            Console.WriteLine("Sending SMS...");

            SMSCAPI obj = new ();
            string strPostResponse;
            strPostResponse = obj.SendSMS(_smsConfig.Username, _smsConfig.Password, number, message);
            Console.WriteLine("Server Response " + strPostResponse);

            Console.WriteLine("Done sending SMS...");
            return Task.CompletedTask;
        }
    }
}
