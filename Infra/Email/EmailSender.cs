using Microsoft.AspNetCore.Identity.UI.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace Infra.Services.Email
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailConfiguration _emailConfig;
        public EmailSender(EmailConfiguration emailConfig)
        {
            _emailConfig = emailConfig;
        }
        public async Task SendEmailAsync(string emailAddresses, string subject, string htmlMessage)
        {
            Console.WriteLine("Sending mail...");

            MailMessage message = new()
            {
                From = new MailAddress(_emailConfig.MailAddress),
                Subject = subject,
                IsBodyHtml = true,
                Body = htmlMessage
            };
            // we assume emails will be sepated by ";"
            foreach (string emailId in emailAddresses.Split(";"))
            {
                message.To.Add(emailId);
            }

            // since we are not getting entries in sent mail, we will add mail manually
            if (!emailAddresses.Split(";").ToList().Any(em => em == _emailConfig.MailAddress))
            {
                // add sender mail if not present in to addresses
                message.To.Add(_emailConfig.MailAddress);
            }

            using (var smtpClient = new SmtpClient())
            {
                smtpClient.Host = _emailConfig.HostName;
                smtpClient.Port = 587;
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_emailConfig.Username, _emailConfig.Password, _emailConfig.Domain);
                smtpClient.Timeout = (60 * 5 * 1000);
                await smtpClient.SendMailAsync(message);
            }

            Console.WriteLine("Done sending mail...");
        }
    }
}