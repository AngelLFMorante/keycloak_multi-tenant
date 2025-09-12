package com.example.keycloak.multitenant.service.mail;

import com.example.keycloak.multitenant.exception.MailSendingException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
public class MailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    public MailService(JavaMailSender mailSender, TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    public void sendSetPasswordEmail(String to, String username, String link) {
        try {
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("link", link);

            String htmlContent = templateEngine.process("verify-email-user", context);

            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject("Activa tu cuenta y crea tu contraseña");
            helper.setText(htmlContent, true); // true = HTML

            mailSender.send(msg);
        } catch (MessagingException ex) {
            throw new MailSendingException("No se pudo enviar el correo a " + to, ex);
        }
    }
}
