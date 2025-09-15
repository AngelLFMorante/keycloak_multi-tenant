package com.example.keycloak.multitenant.service.mail;

import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.TemplateEngine;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private TemplateEngine templateEngine;

    @InjectMocks
    private MailService mailService;

    private MimeMessage mimeMessage;

    @BeforeEach
    void setUp() {
        mimeMessage = mock(MimeMessage.class);
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
    }

    @Test
    @DisplayName("Debe enviar el correo correctamente")
    void sendSetPasswordEmail_ok() {
        when(templateEngine.process(eq("verify-email-user"), any()))
                .thenReturn("<html>OK</html>");

        assertDoesNotThrow(() ->
                mailService.sendSetPasswordEmail("user@test.com", "john", "http://link")
        );

        verify(templateEngine).process(eq("verify-email-user"), any());
        verify(mailSender).createMimeMessage();
        verify(mailSender).send(mimeMessage);
    }

    @Test
    @DisplayName("Debe propagar MailSendException si mailSender falla al enviar")
    void sendSetPasswordEmail_throwMailException() {
        when(templateEngine.process(eq("verify-email-user"), any()))
                .thenReturn("<html>OK</html>");

        doThrow(new MailSendException("fallo al enviar"))
                .when(mailSender).send(any(MimeMessage.class));

        MailSendException ex = assertThrows(
                MailSendException.class,
                () -> mailService.sendSetPasswordEmail("user@test.com", "john", "http://link")
        );

        assertTrue(ex.getMessage().contains("fallo al enviar"));
    }
}
