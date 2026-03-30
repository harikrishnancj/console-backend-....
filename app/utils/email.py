import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.core.config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, 
    SMTP_PASSWORD, SMTP_FROM_EMAIL, 
    SMTP_FROM_NAME
)


async def send_otp_email(email: str, otp: str) -> bool:

    message = MIMEMultipart("alternative")
    message["Subject"] = "Your Verification Code"
    message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    message["To"] = email
    

    text = f"""
Verify Your Email

Your verification code is: {otp}

This code will expire in 5 minutes.

If you didn't request this code, please ignore this email.
    """
    
    # Email body - HTML version
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" style="width: 100%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px 40px; text-align: center;">
                            <h1 style="margin: 0; color: #4F46E5; font-size: 28px; font-weight: 600;">
                                Verify Your Email
                            </h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 0 40px 30px 40px;">
                            <p style="margin: 0 0 20px 0; color: #333333; font-size: 16px; line-height: 1.6; text-align: center;">
                                Enter this verification code to complete your registration:
                            </p>
                            
                            <!-- OTP Code Box -->
                            <table role="presentation" style="width: 100%; border-collapse: collapse;">
                                <tr>
                                    <td align="center" style="padding: 20px 0;">
                                        <div style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                                    padding: 20px 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                                            <span style="font-size: 36px; font-weight: bold; color: #ffffff; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                                                {otp}
                                            </span>
                                        </div>
                                    </td>
                                </tr>
                            </table>
                            
                            <p style="margin: 20px 0 0 0; color: #666666; font-size: 14px; line-height: 1.6; text-align: center;">
                                This code is valid for <strong>5 minutes</strong>.
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 30px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; color: #6b7280; font-size: 12px; line-height: 1.5; text-align: center;">
                                <strong>🔒 Security Notice</strong>
                            </p>
                            <p style="margin: 10px 0 0 0; color: #6b7280; font-size: 12px; line-height: 1.5; text-align: center;">
                                Never share this code with anyone. We will never ask for your verification code.
                            </p>
                            <p style="margin: 10px 0 0 0; color: #6b7280; font-size: 12px; line-height: 1.5; text-align: center;">
                                If you didn't request this code, please ignore this email.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    """
    
    # Attach both versions
    message.attach(MIMEText(text, "plain"))
    message.attach(MIMEText(html, "html"))
    
    # Send email
    try:
        await aiosmtplib.send(
            message,
            hostname=SMTP_HOST,
            port=SMTP_PORT,
            username=SMTP_USER,
            password=SMTP_PASSWORD,
            start_tls=True,
            timeout=10
        )
        print(f"OTP email sent successfully to {email}")
        return True
    except Exception as e:
        print(f"Error sending email to {email}: {str(e)}")
        return False
