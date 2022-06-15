# import asyncio
# import time
# from os import getenv
# from subprocess import PIPE, STDOUT, Popen, TimeoutExpired
# from unittest import TestCase

# import nest_asyncio  # type: ignore
# from supertokens_python.ingredients.emaildelivery.services.smtp import (
#     GetContentResult, SMTPServiceConfig, SMTPServiceConfigFrom, Transporter)


# class TransporterTests(TestCase):
#     def test_transporter(self):  # pylint: disable=no-self-use
#         local_insecure_smtpd_config_without_auth = SMTPServiceConfig(
#             host="localhost",
#             from_=SMTPServiceConfigFrom("Foo bar", "foo@example.com"),
#             port=1025,
#             secure=False,
#         )

#         transporter = Transporter(
#             smtp_settings=local_insecure_smtpd_config_without_auth,
#         )

#         content = GetContentResult(
#             body="<h1>Hello world</h1>",
#             subject='Greetings',
#             to_email='bar@example.com',
#             is_html=True,
#         )

#         command = "python3 -u -m smtpd -c DebuggingServer -n localhost:1025"
#         proc = Popen(command.split(), stdout=PIPE, stderr=STDOUT)  # Starts a SMTP daemon

#         is_sent = False

#         def send_email():
#             nonlocal is_sent
#             loop = asyncio.get_event_loop()
#             nest_asyncio.apply(loop)  # type: ignore
#             loop.run_until_complete(transporter.send_email(content, {}))
#             is_sent = True

#         try:
#             time.sleep(0.2)
#             send_email()
#         finally:
#             proc.terminate()
#             try:
#                 out, _ = proc.communicate(timeout=0.5)
#                 out = out.decode('utf-8').replace("\\n", "\n")
#                 assert out != ""
#                 assert out == """---------- MESSAGE FOLLOWS ----------
# b'Content-Type: text/html; charset="us-ascii"'
# b'MIME-Version: 1.0'
# b'Content-Transfer-Encoding: 7bit'
# b'From: Foo bar <foo@example.com>'
# b'To: bar@example.com'
# b'Subject: Greetings'
# b'X-Peer: 127.0.0.1'
# b''
# b'<h1>Hello world</h1>'
# ------------ END MESSAGE ------------
# """
#             except TimeoutExpired:
#                 raise Exception('subprocess did not terminate in time')

#     def test_transporter_with_gmail(self):  # pylint: disable=no-self-use
#         email = getenv("TEST_GMAIL_EMAIL")
#         password = getenv("TEST_GMAIL_PASS")

#         if not (email and password):
#             # Skip test if env vars aren't provided
#             return

#         real_gmail_smtp_config = SMTPServiceConfig(
#             host="smtp.gmail.com",
#             from_=SMTPServiceConfigFrom("ST Demo", email),
#             password=password,
#             port=465,  # alternatively, port=587, secure=False should also work
#             secure=True,
#         )

#         transporter = Transporter(
#             smtp_settings=real_gmail_smtp_config,
#         )

#         content = GetContentResult(
#             body="<h1>Hello world</h1>",
#             subject='Greetings',
#             to_email=email,
#             is_html=True,
#         )

#         loop = asyncio.get_event_loop()
#         nest_asyncio.apply(loop)  # type: ignore
#         loop.run_until_complete(transporter.send_email(content, {}))
