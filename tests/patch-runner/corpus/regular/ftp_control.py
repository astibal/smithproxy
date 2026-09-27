from _common import script

PPlayScript = script("ftp_control", [
    b"220 FTP ready\r\n", b"USER anonymous\r\n", b"331 Password required\r\n",
    b"PASS pplay@example.test\r\n", b"230 Logged in\r\n", b"SYST\r\n", b"215 UNIX Type: L8\r\n",
    b"QUIT\r\n", b"221 Goodbye\r\n",
], "scscscscs")
