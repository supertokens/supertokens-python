# Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
#
# This software is licensed under the Apache License, Version 2.0 (the
# "License") as published by the Apache Software Foundation.
#
# You may not use this file except in compliance with the License. You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import ssl
from email.mime.text import MIMEText
from typing import Any, Dict, TypeVar

import aiosmtplib
from supertokens_python.ingredients.emaildelivery.types import (
    EmailContent,
    SMTPSettings,
)
from supertokens_python.logger import log_debug_message

_T = TypeVar("_T")


class Transporter:
    def __init__(self, smtp_settings: SMTPSettings) -> None:
        self.smtp_settings = smtp_settings

    async def _connect(self):
        try:
            tls_context = ssl.create_default_context()
            if self.smtp_settings.secure:
                # Use TLS from the beginning
                mail = aiosmtplib.SMTP(
                    self.smtp_settings.host,
                    self.smtp_settings.port,
                    use_tls=True,
                    tls_context=tls_context,
                )
            else:
                # Start without TLS (but later try upgrading)
                mail = aiosmtplib.SMTP(
                    self.smtp_settings.host, self.smtp_settings.port, use_tls=False
                )

            await mail.connect()  # type: ignore

            if not self.smtp_settings.secure:
                # Try upgrading to TLS (even if the user opted for secure=False)
                try:
                    await mail.starttls(tls_context=tls_context)
                except aiosmtplib.SMTPException:  # TLS wasn't supported by the server, so ignore.
                    pass

            if self.smtp_settings.password:
                await mail.login(
                    self.smtp_settings.username or self.smtp_settings.from_.email,
                    self.smtp_settings.password,
                )

            return mail
        except Exception as e:
            log_debug_message("Couldn't connect to the SMTP server: %s", e)
            raise e

    async def send_email(self, input_: EmailContent, _: Dict[str, Any]) -> None:
        connection = await self._connect()

        from_ = self.smtp_settings.from_
        try:
            from_addr = f"{from_.name} <{from_.email}>"
            if input_.is_html:
                email_content = MIMEText(input_.body, "html")
                email_content["From"] = from_addr
                email_content["To"] = input_.to_email
                email_content["Subject"] = input_.subject
                await connection.sendmail(
                    from_.email, input_.to_email, email_content.as_string()
                )
            else:
                await connection.sendmail(from_addr, input_.to_email, input_.body)
        except Exception as e:
            log_debug_message("Error in sending email: %s", e)
            raise e
        finally:
            await connection.quit()
