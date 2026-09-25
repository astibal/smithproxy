from _common import script

PPlayScript = script("imap_dialog", [
    b"* OK IMAP4rev1 Service Ready\r\n",
    b"a001 CAPABILITY\r\n",
    b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\na001 OK CAPABILITY completed\r\n",
    b"a002 LOGOUT\r\n",
    b"* BYE logging out\r\na002 OK LOGOUT completed\r\n",
], "scscs")
