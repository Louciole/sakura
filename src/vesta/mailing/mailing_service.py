import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils
import dkim


class Mailing:
    def __init__(self, host, port, address, password, serviceName, path):
        try:
            self.name = serviceName
            self.host = host
            self.port = port
            self.password = password
            self.smtp = smtplib.SMTP(host, port)
            self.smtp.ehlo()  # send the extended hello to our server
            self.smtp.starttls()
            self.address = address
            self.smtp.login(address, password)
            self.templates = {}
            self.path = path
            with open(self.path + "/mailing/dkim.txt") as fh:
                self.private = fh.read()
            print("[Vesta - mails] server connected")
        except smtplib.SMTPException as e:
            print(f"Error connecting to mailing server : {e}")
            self.smtp.quit()

    def restart(self):
        self.smtp = smtplib.SMTP(self.host, self.port)
        self.smtp.ehlo()  # send the extended hello to our server
        self.smtp.starttls()
        self.smtp.login(self.address, self.password)
        print("[Vesta - mails] server reconnected")

    def is_connected(conn):
        try:
            status = conn.noop()[0]
        except:  # smtplib.SMTPServerDisconnected
            status = -1
        return True if status == 250 else False

    def sendMail(self, content):
        if not self.is_connected():
            self.restart()
        try:
            self.smtp.send_message(content)
            print("[Vesta - mails] mail sent")
        except smtplib.SMTPException as e:
            print(f"Error sending a mail : {e}")

    def sendTemplate(self,template,target,subject,text,values):
        try:
            self.templates[template]
        except:
            f = open(self.path + "/mailing/" + template, "r")
            self.templates[template] = f.read()
            f.close()

        mail_confirmation = MIMEMultipart('alternative')
        mail_confirmation['Subject'] = subject
        mail_confirmation['From'] = self.name + " <" + self.address + ">"
        mail_confirmation['Message-ID'] = email.utils.make_msgid(domain='carbonlab.dev')
        mail_confirmation['Date'] = email.utils.formatdate()
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(self.templates[template].format(values), 'html')
        mail_confirmation.attach(part1)
        mail_confirmation.attach(part2)
        mail_confirmation['To'] = target  # ATTENTION CE N'EST PAS UNE COPIE CACHEE
        self.signMail(mail_confirmation)
        self.sendMail(mail_confirmation)

    def signMail(self, mail):
        headers = ["To", "From", "Subject"]
        sig = dkim.sign(
            message=mail.as_bytes(),
            selector="1686741263.carbonlab".encode(),
            domain="carbonlab.dev".encode(),
            privkey=self.private.encode(),
            include_headers=headers, )
        mail["DKIM-Signature"] = sig[len("DKIM-Signature: "):].decode()

    def sendConfirmation(self, target, OTP):
        try:
            self.template_confirmation
        except:
            f = open(self.path + "/mailing/mailVerif.html", "r")
            self.template_confirmation = f.read()
            f.close()

        mail_confirmation = MIMEMultipart('alternative')
        mail_confirmation['Subject'] = "🌱 Confirmez votre adresse ! 📨"
        mail_confirmation['From'] = self.name + " <" + self.address + ">"
        mail_confirmation['Message-ID'] = email.utils.make_msgid(domain='carbonlab.dev')
        mail_confirmation['Date'] = email.utils.formatdate()
        text = "Confirm your " + self.name + " account : " + OTP
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(self.template_confirmation.format(OTP), 'html')
        mail_confirmation.attach(part1)
        mail_confirmation.attach(part2)
        mail_confirmation['To'] = target  # ATTENTION CE N'EST PAS UNE COPIE CACHEE
        self.signMail(mail_confirmation)
        self.sendMail(mail_confirmation)

    def sendOrgInvite(self, target, company):
        try:
            self.template_org_invitation
        except:
            f = open(self.path + "/mailing/mailInvite.html", "r")
            self.template_org_invitation = f.read()
            f.close()
            self.mail_invitation = MIMEMultipart('alternative')
            self.mail_invitation['Subject'] = "🔔 Rejoignez " + company + " 🔔"
            self.mail_invitation['From'] = self.name + " <" + self.address + ">"

        self.mail_invitation['Message-ID'] = email.utils.make_msgid(domain='carbonlab.dev')
        self.mail_invitation['Date'] = email.utils.formatdate()
        text = "Inscrivez vous sur " + self.name + " pour rejoindre " + company
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(self.template_org_invitation.format(company,company), 'html')
        self.mail_invitation.attach(part1)
        self.mail_invitation.attach(part2)
        self.mail_invitation['To'] = target  # ATTENTION CE N'EST PAS UNE COPIE CACHEE
        self.signMail(self.mail_invitation)

        self.sendMail(self.mail_invitation)
