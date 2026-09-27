from _common import script

PPlayScript = script("smtp_dialog", [
    b"220 mail.runner.lab ESMTP\r\n",
    b"EHLO client.runner.lab\r\n",
    b"250-mail.runner.lab\r\n250 SIZE 1048576\r\n",
    b"MAIL FROM:<sender@example.test>\r\n",
    b"250 2.1.0 OK\r\n",
    b"RCPT TO:<receiver@example.test>\r\n",
    b"250 2.1.5 OK\r\n",
    b"QUIT\r\n",
    b"221 2.0.0 Bye\r\n",
], "scscscscs")
