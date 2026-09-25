from _common import script

PPlayScript = script("pop3_dialog", [
    b"+OK POP3 server ready\r\n", b"USER alice\r\n", b"+OK\r\n", b"PASS secret\r\n",
    b"+OK mailbox locked\r\n", b"STAT\r\n", b"+OK 2 320\r\n", b"QUIT\r\n", b"+OK bye\r\n",
], "scscscscs")
