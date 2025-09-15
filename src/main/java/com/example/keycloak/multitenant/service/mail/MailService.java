package com.example.keycloak.multitenant.service.mail;

import com.example.keycloak.multitenant.exception.MailSendingException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

/**
 * Servicio para el envío de correos electrónicos.
 * <p>
 * Se encarga de la construcción del contenido del correo utilizando plantillas de Thymeleaf
 * y del envío a través de Spring Mail. Las excepciones de envío son encapsuladas
 * en una excepción personalizada {@link MailSendingException}.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class MailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    /**
     * Constructor para inyección de dependencias.
     *
     * @param mailSender     El remitente de correo de Spring Mail.
     * @param templateEngine El motor de plantillas de Thymeleaf.
     */
    public MailService(JavaMailSender mailSender, TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    /**
     * Envía un correo electrónico al usuario para la verificación de cuenta y el
     * establecimiento de la contraseña inicial.
     * <p>
     * Utiliza la plantilla "verify-email-user" de Thymeleaf y la rellena
     * con el nombre de usuario y el enlace de activación.
     *
     * @param to       El destinatario del correo (dirección de correo electrónico del usuario).
     * @param username El nombre de usuario que se mostrará en la plantilla.
     * @param link     El enlace de activación para que el usuario establezca su contraseña.
     * @throws MailSendingException Si ocurre un error al construir o enviar el correo.
     */
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
